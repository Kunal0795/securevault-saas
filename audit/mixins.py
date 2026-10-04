import logging

from .emit import emit_audit_event

logger = logging.getLogger(__name__)

ACTION_VERBS = {
    'list': 'list',
    'retrieve': 'read',
    'create': 'create',
    'update': 'update',
    'partial_update': 'update',
    'destroy': 'delete',
}


class AuditedViewSetMixin:
    """Emits one audit event per authenticated, tenant-bound ViewSet request (any outcome)."""

    audit_resource_type = None  # defaults to the router basename, e.g. 'document'

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        try:
            self._emit_audit(request, response)
        except Exception:
            logger.exception('audit hook failed')
        return response

    def _emit_audit(self, request, response):
        verb = ACTION_VERBS.get(getattr(self, 'action', None))
        user = request.user
        if verb is None or not getattr(user, 'is_authenticated', False) or not user.tenant_id:
            return
        status = response.status_code
        if status < 400:
            outcome = 'success'
        elif status in (401, 403):
            outcome = 'denied'
        else:
            outcome = 'failure'
        resource_type = self.audit_resource_type or self.basename
        resource_id = self.kwargs.get(self.lookup_url_kwarg or self.lookup_field, '')
        if not resource_id and status < 400 and isinstance(response.data, dict):
            resource_id = response.data.get('id', '')  # create: id of the new object
        emit_audit_event(
            tenant_id=user.tenant_id,
            action=f'{resource_type}.{verb}',
            outcome=outcome,
            actor=user,
            resource_type=resource_type,
            resource_id=resource_id,
            request=request,
            metadata={'method': request.method, 'path': request.path, 'status': status},
        )
