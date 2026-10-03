from django.db.models import Q
from rest_framework.permissions import SAFE_METHODS, BasePermission

# Stored values: these MUST match the TextChoices on CustomUser.role and
# Document.sensitivity (verify with the pre-flight shell command).
ADMIN, MEMBER, VIEWER = "ADMIN", "MEMBER", "VIEWER"
PUBLIC, INTERNAL, CONFIDENTIAL = "PUBLIC", "INTERNAL", "CONFIDENTIAL"


class RolePermission(BasePermission):
    """
    RBAC: coarse, action-level gate. Which *verbs* may this role use at all?
    Runs on every request (list, retrieve, create, update, delete).
    """

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if user.role in (ADMIN, MEMBER):
            return True
        if user.role == VIEWER:
            return request.method in SAFE_METHODS
        return False  # unknown role -> fail closed


def visible_documents(user, queryset):
    """
    ABAC read-visibility expressed as a queryset filter.

    DRF never calls has_object_permission() on list, so list results must be
    filtered here. get_object() also uses get_queryset(), so a document the
    user may not read is a 404 on detail routes too: no existence oracle.
    """
    if user.role == ADMIN:
        return queryset
    if user.role == MEMBER:
        # PUBLIC/INTERNAL tenant-wide, CONFIDENTIAL only if they own it.
        # created_by IS NULL never matches created_by=user -> fail closed.
        return queryset.filter(
            Q(sensitivity__in=[PUBLIC, INTERNAL]) | Q(created_by=user)
        )
    if user.role == VIEWER:
        return queryset.filter(sensitivity__in=[PUBLIC, INTERNAL])
    return queryset.none()  # unknown role -> sees nothing


class DocumentAccessPolicy(BasePermission):
    """
    ABAC: fine-grained, object-level decision from attributes of the user
    (role, tenant, id) and the object (tenant, owner, sensitivity).
    Fires only on detail routes: retrieve / update / partial_update / destroy.

    The read rules duplicate visible_documents() on purpose (defense in depth):
    if get_queryset() is ever changed or overridden wrongly, this still denies.
    """

    def has_object_permission(self, request, view, obj):
        user = request.user

        # Layer 3 tenant check (layers 1-2 are Postgres RLS + queryset filter)
        if obj.tenant_id != user.tenant_id:
            return False

        if user.role == ADMIN:
            return True

        is_owner = obj.created_by_id == user.id
        is_confidential = obj.sensitivity == CONFIDENTIAL

        if request.method in SAFE_METHODS:
            if user.role == MEMBER:
                return (not is_confidential) or is_owner
            if user.role == VIEWER:
                return not is_confidential
            return False

        # Writes (PUT / PATCH / DELETE): owners only. Viewers never get here
        # (RolePermission already blocked them) but we fail closed regardless.
        return user.role == MEMBER and is_owner