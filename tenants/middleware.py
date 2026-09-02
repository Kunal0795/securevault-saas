from django.db import connection
from django.http import JsonResponse
from tenants.models import Tenant


class TenantMiddleware:
    EXEMPT_PATHS = (
        '/api/token/',
        '/admin/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(self.EXEMPT_PATHS):
            return self.get_response(request)

        tenant_id = request.headers.get('X-Tenant-ID')

        if not tenant_id:
            return JsonResponse({'error': 'X-Tenant-ID header is required'}, status=400)

        if not Tenant.objects.filter(id=tenant_id, is_active=True).exists():
            return JsonResponse({'error': 'Invalid or inactive tenant'}, status=403)

        with connection.cursor() as cursor:
            cursor.execute("SET app.current_tenant_id = %s", [tenant_id])

        response = self.get_response(request)
        return response