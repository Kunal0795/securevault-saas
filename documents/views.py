from rest_framework import viewsets, permissions
from .models import Document
from .serializers import DocumentSerializer
from .permissions import RolePermission


class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [permissions.IsAuthenticated, RolePermission]  # RolePermission/DocumentAccessPolicy plug in here in Steps 4-5
    # ... get_queryset and perform_create stay exactly as they are

    def get_queryset(self):
        # Defense-in-depth: PostgreSQL RLS already restricts visible rows via the
        # app.current_tenant_id session var (set in TenantMiddleware). This explicit
        # filter is a SECOND, independent layer — if RLS were ever misconfigured or
        # the session var failed to set, this still blocks cross-tenant reads.
        return Document.objects.filter(tenant=self.request.user.tenant)

    def perform_create(self, serializer):
        # tenant and created_by are never trusted from client input — always derived
        # from the authenticated request. Pairs with read_only_fields in the serializer.
        serializer.save(tenant=self.request.user.tenant, created_by=self.request.user)












