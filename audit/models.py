import uuid

from django.db import models


class ImmutableAuditError(Exception):
    """Raised on any attempt to modify or delete an audit row."""


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ImmutableAuditError("AuditLog rows are append-only: update blocked")

    def delete(self):
        raise ImmutableAuditError("AuditLog rows are append-only: delete blocked")


class AuditLog(models.Model):
    class Outcome(models.TextChoices):
        SUCCESS = 'success', 'Success'
        DENIED = 'denied', 'Denied'
        FAILURE = 'failure', 'Failure'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_id = models.UUIDField(unique=True)  # idempotency key, set when the event is emitted
    tenant = models.ForeignKey(
        'tenants.Tenant', on_delete=models.PROTECT, related_name='audit_logs'
    )
    sequence = models.PositiveBigIntegerField()  # per-tenant, starts at 1
    occurred_at = models.DateTimeField()
    actor_id = models.UUIDField(null=True, blank=True)  # no FK: deleting a user must not touch audit rows
    actor_username = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=64)
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    resource_type = models.CharField(max_length=64, blank=True)
    resource_id = models.CharField(max_length=64, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=256, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64, unique=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'sequence'], name='audit_unique_tenant_sequence'
            ),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ImmutableAuditError("AuditLog rows are append-only: save on existing row blocked")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ImmutableAuditError("AuditLog rows are append-only: delete blocked")

    def __str__(self):
        return f"{self.tenant_id}#{self.sequence} {self.action}"
