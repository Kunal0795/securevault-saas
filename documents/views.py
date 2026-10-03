from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Document
from .permissions import DocumentAccessPolicy, RolePermission, visible_documents
from .serializers import DocumentSerializer


class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated, RolePermission, DocumentAccessPolicy]

    def get_queryset(self):
        user = self.request.user
        # Layer: app-level tenant filter (Postgres RLS is the layer beneath it),
        # then ABAC read-visibility on top.
        qs = Document.objects.filter(tenant=user.tenant)
        return visible_documents(user, qs)

    def perform_create(self, serializer):
        # tenant / created_by come from the authenticated user, never the client
        serializer.save(
            tenant=self.request.user.tenant,
            created_by=self.request.user,
        )