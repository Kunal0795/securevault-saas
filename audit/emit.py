import logging
import uuid

from django.db import transaction
from django.utils import timezone

from .tasks import write_audit_event

logger = logging.getLogger(__name__)


def emit_audit_event(*, tenant_id, action, outcome, actor=None, resource_type='',
                     resource_id='', request=None, metadata=None):
    """Queue an audit event. Never raises: auditing must not break the request."""
    try:
        event = {
            'event_id': str(uuid.uuid4()),
            'tenant_id': str(tenant_id),
            'occurred_at': timezone.now().isoformat(),
            'actor_id': str(actor.pk) if actor is not None else None,
            'actor_username': getattr(actor, 'username', '') if actor is not None else '',
            'action': action,
            'outcome': outcome,
            'resource_type': resource_type,
            'resource_id': str(resource_id) if resource_id else '',
            # REMOTE_ADDR only: X-Forwarded-For is client-controlled unless a trusted proxy sets it
            'ip_address': request.META.get('REMOTE_ADDR') if request is not None else None,
            'user_agent': request.META.get('HTTP_USER_AGENT', '') if request is not None else '',
            'metadata': metadata or {},
        }
        transaction.on_commit(lambda: _publish(event))
    except Exception:
        logger.exception('audit emit failed (action=%s)', action)


def _publish(event):
    try:
        write_audit_event.apply_async(args=[event], retry=False)
    except Exception:
        logger.exception('audit publish failed (event_id=%s)', event['event_id'])
