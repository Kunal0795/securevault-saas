# tenants/middleware.py
from django.db import connection
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from tenants.models import Tenant


class TenantMiddleware:
    EXEMPT_PATHS = (
        '/api/token/',
        '/admin/',
    )

    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_authenticator = JWTAuthentication()

    def __call__(self, request):
        if request.path.startswith(self.EXEMPT_PATHS):
            return self.get_response(request)

        tenant_id = None

        try:
            auth_result = self.jwt_authenticator.authenticate(request)
        except (InvalidToken, AuthenticationFailed):
            auth_result = None

        if auth_result is not None:
            user, token = auth_result
            if user.tenant_id:
                tenant_id = str(user.tenant_id)

        if not tenant_id:
            return JsonResponse(
                {'error': 'Valid authentication with an assigned tenant is required'},
                status=401,
            )

        if not Tenant.objects.filter(id=tenant_id, is_active=True).exists():
            return JsonResponse({'error': 'Invalid or inactive tenant'}, status=403)

        with connection.cursor() as cursor:
            cursor.execute("SET app.current_tenant_id = %s", [tenant_id])

        return self.get_response(request)