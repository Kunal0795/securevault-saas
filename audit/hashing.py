import hashlib
import json
from datetime import timezone

GENESIS_HASH = '0' * 64
HASH_VERSION = 1


def format_ts(dt):
    """Fixed-width UTC timestamp: always 6 fractional digits, always 'Z'."""
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def canonical_bytes(payload):
    """Deterministic JSON: sorted keys, no whitespace, ASCII only, no NaN."""
    return json.dumps(
        payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False
    ).encode('ascii')


def build_payload(*, tenant_id, sequence, event_id, occurred_at, actor_id, actor_username,
                  action, outcome, resource_type, resource_id, ip_address, user_agent,
                  metadata, prev_hash):
    return {
        'v': HASH_VERSION,
        'tenant_id': str(tenant_id),
        'sequence': sequence,
        'event_id': str(event_id),
        'occurred_at': format_ts(occurred_at),
        'actor_id': str(actor_id) if actor_id else None,
        'actor_username': actor_username,
        'action': action,
        'outcome': outcome,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'ip_address': str(ip_address) if ip_address else None,
        'user_agent': user_agent,
        'metadata': metadata,
        'prev_hash': prev_hash,
    }


def compute_entry_hash(payload):
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def payload_from_log(log):
    """Rebuild the hashed payload from a stored AuditLog row (used for verification)."""
    return build_payload(
        tenant_id=log.tenant_id, sequence=log.sequence, event_id=log.event_id,
        occurred_at=log.occurred_at, actor_id=log.actor_id,
        actor_username=log.actor_username, action=log.action, outcome=log.outcome,
        resource_type=log.resource_type, resource_id=log.resource_id,
        ip_address=log.ip_address, user_agent=log.user_agent, metadata=log.metadata,
        prev_hash=log.prev_hash,
    )