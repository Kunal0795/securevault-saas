from rest_framework.permissions import BasePermission, SAFE_METHODS
from accounts.models import CustomUser


class RolePermission(BasePermission):
    """
    RBAC — coarse, action-level gate: can this ROLE ever perform this
    kind of HTTP method, independent of which specific object is involved.
    Ownership/sensitivity checks live in DocumentAccessPolicy (Step 5).
    """

    def has_permission(self, request, view):
        role = getattr(request.user, 'role', None)

        if request.method in SAFE_METHODS:
            # GET/HEAD/OPTIONS — every authenticated role may attempt to read.
            # WHICH documents they actually see is filtered elsewhere
            # (get_queryset + DocumentAccessPolicy), not here.
            return True

        if role == CustomUser.RoleChoices.VIEWER:
            # VIEWER is read-only — blocked from POST/PUT/PATCH/DELETE outright
            return False

        return True  # ADMIN, MEMBER may attempt writes; object-level checks follow