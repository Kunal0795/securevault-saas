import json
import uuid
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from audit.hashing import GENESIS_HASH, compute_entry_hash, payload_from_log
from audit.models import AuditLog
from tenants.models import Tenant

BATCH = 1000


class Command(BaseCommand):
    help = 'Verify the SHA-256 audit hash chain of every tenant (or one tenant).'

    def add_arguments(self, parser):
        parser.add_argument('--tenant', help='tenant slug or UUID (default: all tenants)')
        parser.add_argument('--anchor-file',
                            help='JSON file of trusted chain heads, kept outside the database')
        parser.add_argument('--update-anchor', action='store_true',
                            help='after a clean run, save the current chain heads to --anchor-file')

    def handle(self, *args, **opts):
        tenants = Tenant.objects.order_by('slug')
        if opts['tenant']:
            key = opts['tenant']
            try:
                tenants = tenants.filter(pk=uuid.UUID(key))
            except ValueError:
                tenants = tenants.filter(slug=key)
            if not tenants.exists():
                raise CommandError(f'no such tenant: {key}')

        anchor_path = Path(opts['anchor_file']).expanduser() if opts['anchor_file'] else None
        if opts['update_anchor'] and anchor_path is None:
            raise CommandError('--update-anchor needs --anchor-file')
        anchors = {}
        if anchor_path is not None and anchor_path.exists():
            anchors = json.loads(anchor_path.read_text())
        elif anchor_path is not None and not opts['update_anchor']:
            raise CommandError(f'anchor file not found: {anchor_path}')

        failures = 0
        heads = dict(anchors)  # keep anchors of tenants not checked in this run
        for tenant in tenants:
            anchor = anchors.get(str(tenant.pk))
            problem, count, head = self._verify_tenant(tenant, anchor)
            if problem:
                failures += 1
                self.stdout.write(self.style.ERROR(f'{tenant.slug}: BROKEN - {problem}'))
                continue
            note = ' (anchor checked)' if anchor else ''
            self.stdout.write(self.style.SUCCESS(f'{tenant.slug}: OK - {count} entries{note}'))
            if head:
                heads[str(tenant.pk)] = head

        if failures:
            raise CommandError(f'{failures} tenant chain(s) failed verification')
        if opts['update_anchor']:
            anchor_path.write_text(json.dumps(heads, indent=2, sort_keys=True))
            anchor_path.chmod(0o600)
            self.stdout.write(f'anchors saved to {anchor_path}')

    def _verify_tenant(self, tenant, anchor):
        """Returns (problem or None, entries verified, head or None)."""
        expected = 1
        prev_hash = GENESIS_HASH
        anchor_ok = anchor is None
        with transaction.atomic():
            with connection.cursor() as cur:
                # transaction-local tenant context, needed for RLS
                cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", [str(tenant.pk)])
            last = 0
            while True:
                batch = list(
                    AuditLog.objects.filter(tenant_id=tenant.pk, sequence__gt=last)
                    .order_by('sequence')[:BATCH]
                )
                if not batch:
                    break
                for row in batch:
                    if row.sequence != expected:
                        return (f'sequence gap: expected {expected}, found {row.sequence} '
                                f'(entries missing or reordered)', expected - 1, None)
                    if row.prev_hash != prev_hash:
                        return (f'broken link at sequence {row.sequence}: prev_hash does not '
                                f'match the previous entry', expected - 1, None)
                    if compute_entry_hash(payload_from_log(row)) != row.entry_hash:
                        return (f'content altered at sequence {row.sequence}: stored hash does '
                                f'not match the recomputed hash', expected - 1, None)
                    if anchor is not None and row.sequence == anchor['sequence']:
                        if row.entry_hash != anchor['entry_hash']:
                            return (f'anchor mismatch at sequence {row.sequence}: history up to '
                                    f'the anchor was rewritten', expected - 1, None)
                        anchor_ok = True
                    prev_hash = row.entry_hash
                    expected += 1
                last = batch[-1].sequence
        if not anchor_ok:
            return (f'chain truncated: it ends at sequence {expected - 1}, but a trusted anchor '
                    f'exists at sequence {anchor["sequence"]}', expected - 1, None)
        head = {'sequence': expected - 1, 'entry_hash': prev_hash} if expected > 1 else None
        return None, expected - 1, head
