
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone as dt_timezone

from celery import shared_task
from django.db import OperationalError, connection, transaction

from .hashing import GENESIS_HASH, build_payload, canonical_bytes, compute_entry_hash
from .models import AuditLog

logger = logging.getLogger(__name__)

ACTION_RE = re.compile(r'[a-z0-9_.]{1,64}')
REQUIRED_KEYS = {'event_id', 'tenant_id', 'occurred_at', 'action', 'outcome'}
OPTIONAL_KEYS = {'actor_id', 'actor_username', 'resource_type', 'resource_id',
                 'ip_address', 'user_agent', 'metadata'}
MAX_METADATA_BYTES = 8192
MAX_DEPTH = 6


def _text(value, limit):
    if value is None:
        return ''
    if not isinstance(value, str):
        raise ValueError('text field must be a string')
    return value.replace('\x00', '\ufffd')[:limit]  # Postgres rejects NUL in text/jsonb


def _clean(value, depth=0):
    """Validate + copy metadata. No floats: JSON/jsonb round-trip is not byte-stable for them."""
    if depth > MAX_DEPTH:
        raise ValueError('metadata nested too deeply')
    if isinstance(value, str):
        return value.replace('\x00', '\ufffd')
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise ValueError('metadata must not contain floats')
    if isinstance(value, list):
        return [_clean(v, depth + 1) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError('metadata keys must be strings')
            out[_clean(k)] = _clean(v, depth + 1)
        return out
    raise ValueError(f'unsupported metadata type: {type(value).__name__}')


def normalize_event(raw):
    """Strict validation. Everything that gets hashed is normalized here, once."""
    if not isinstance(raw, dict):
        raise ValueError('event must be a dict')
    keys = set(raw)
    unknown = keys - REQUIRED_KEYS - OPTIONAL_KEYS
    if unknown:
        raise ValueError(f'unexpected keys: {sorted(unknown)}')
    missing = REQUIRED_KEYS - keys
    if missing:
        raise ValueError(f'missing keys: {sorted(missing)}')
    try:
        occurred_at = datetime.fromisoformat(raw['occurred_at'])
        if occurred_at.tzinfo is None:
            raise ValueError('occurred_at must be timezone-aware')
        action = raw['action']
        if not isinstance(action, str) or not ACTION_RE.fullmatch(action):
            raise ValueError('invalid action')
        if raw['outcome'] not in AuditLog.Outcome.values:
            raise ValueError('invalid outcome')
        metadata = raw.get('metadata', {})
        if not isinstance(metadata, dict):
            raise ValueError('metadata must be a dict')
        metadata = _clean(metadata)
        if len(canonical_bytes(metadata)) > MAX_METADATA_BYTES:
            metadata = {'_dropped': f'metadata exceeded {MAX_METADATA_BYTES} bytes'}
        ip = raw.get('ip_address')
        return {
            'event_id': uuid.UUID(str(raw['event_id'])),
            'tenant_id': uuid.UUID(str(raw['tenant_id'])),
            'occurred_at': occurred_at.astimezone(dt_timezone.utc),
            'actor_id': uuid.UUID(str(raw['actor_id'])) if raw.get('actor_id') else None,
            'actor_username': _text(raw.get('actor_username'), 150),
            'action': action,
            'outcome': raw['outcome'],
            'resource_type': _text(raw.get('resource_type'), 64),
            'resource_id': _text(raw.get('resource_id'), 64),
            'ip_address': str(ipaddress.ip_address(ip)) if ip else None,
            'user_agent': _text(raw.get('user_agent'), 256),
            'metadata': metadata,
        }
    except (TypeError, AttributeError) as exc:
        raise ValueError(f'malformed event: {exc}') from exc


@shared_task(
    name='audit.write_event',
    autoretry_for=(OperationalError,),
    retry_backoff=True,
    retry_backoff_max=60,
    max_retries=5,
)
def write_audit_event(raw_event):
    try:
        ev = normalize_event(raw_event)
    except ValueError:
        event_id = raw_event.get('event_id') if isinstance(raw_event, dict) else None
        logger.error('audit event rejected (event_id=%s)', event_id, exc_info=True)
        raise

    tenant = str(ev['tenant_id'])
    with transaction.atomic():
        with connection.cursor() as cur:
            # transaction-local tenant context (needed for RLS) + per-tenant chain lock
            cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", [tenant])
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ['audit-chain:' + tenant]
            )
        # everything below runs AFTER the lock, so each statement sees the latest committed head
        if AuditLog.objects.filter(event_id=ev['event_id']).exists():
            return 'duplicate'  # at-least-once delivery: replay is a no-op
        head = (
            AuditLog.objects.filter(tenant_id=ev['tenant_id'])
            .order_by('-sequence')
            .values_list('sequence', 'entry_hash')
            .first()
        )
        sequence, prev_hash = (head[0] + 1, head[1]) if head else (1, GENESIS_HASH)
        payload = build_payload(sequence=sequence, prev_hash=prev_hash, **ev)
        AuditLog.objects.create(
            **ev, sequence=sequence, prev_hash=prev_hash,
            entry_hash=compute_entry_hash(payload),
        )
    return 'written'
