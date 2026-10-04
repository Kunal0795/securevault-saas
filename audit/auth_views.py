import logging

from django.contrib.auth import get_user_model
from rest_framework.throttling import SimpleRateThrottle
from rest_framework_simplejwt.exceptions import TokenBackendError
from rest_framework_simplejwt.settings import api_settings as jwt_settings
from rest_framework_simplejwt.state import token_backend
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .emit import emit_audit_event

logger = logging.getLogger(__name__)


class AuthRateThrottle(SimpleRateThrottle):
    """Per-IP limit on the token endpoints. Also bounds how fast anonymous callers can add audit rows."""

    scope = 'auth'
    rate = '30/min'

    def get_cache_key(self, request, view):
        # REMOTE_ADDR only: X-Forwarded-For is client-controlled without a trusted proxy
        return self.cache_format % {
            'scope': self.scope,
            'ident': request.META.get('REMOTE_ADDR', 'unknown'),
        }


def _outcome(status):
    if status < 400:
        return 'success'
    return 'denied' if status in (401, 403) else 'failure'


class _AuditedAuthMixin:
    throttle_classes = [AuthRateThrottle]

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        try:
            # throttled calls are not logged, otherwise a flood would still grow the chain
            if response.status_code != 429:
                self._emit_auth_audit(request, response)
        except Exception:
            logger.exception('auth audit hook failed')
        return response

    def _record(self, request, response, *, action, user, reason=None):
        status = response.status_code
        metadata = {'method': request.method, 'path': request.path, 'status': status}
        if reason:
            metadata['reason'] = reason
        emit_audit_event(
            tenant_id=user.tenant_id,
            action=action,
            outcome=_outcome(status),
            actor=user,
            resource_type='token',
            request=request,
            metadata=metadata,
        )


class AuditedTokenObtainPairView(_AuditedAuthMixin, TokenObtainPairView):
    def _emit_auth_audit(self, request, response):
        username = request.data.get('username')
        user = None
        if isinstance(username, str) and username:
            User = get_user_model()
            user = User.objects.filter(**{User.USERNAME_FIELD: username}).first()
        if user is None or not user.tenant_id:
            logger.info('login not chained (unknown or tenant-less user %r, status=%s)',
                        str(username)[:50], response.status_code)
            return
        self._record(request, response, action='auth.login', user=user)


class AuditedTokenRefreshView(_AuditedAuthMixin, TokenRefreshView):
    def _emit_auth_audit(self, request, response):
        user_id = None
        reason = None
        if response.status_code < 400:
            # freshly minted, signature-verified access token
            user_id = AccessToken(response.data['access'])[jwt_settings.USER_ID_CLAIM]
        else:
            raw = request.data.get('refresh')
            if isinstance(raw, str):
                try:
                    # signature + expiry only. The blacklist is deliberately NOT checked here,
                    # so reuse of an already-rotated token is still attributable.
                    payload = token_backend.decode(raw, verify=True)
                    user_id = payload.get(jwt_settings.USER_ID_CLAIM)
                except TokenBackendError:
                    pass  # forged, expired or garbage: cannot be attributed safely
            detail = response.data.get('detail') if isinstance(response.data, dict) else None
            reason = str(detail)[:100] if detail else None
        user = get_user_model().objects.filter(pk=user_id).first() if user_id else None
        if user is None or not user.tenant_id:
            logger.info('refresh not chained (unattributable token, status=%s)', response.status_code)
            return
        self._record(request, response, action='auth.refresh', user=user, reason=reason)
