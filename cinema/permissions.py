from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAdminOrIfAuthenticatedReadOnly(BasePermission):
    """
    The request is authenticated as an admin - read/write,
    if as a user - read only request.
    """
    def has_permission(self, request, view):
        return bool(
            request.method in SAFE_METHODS
            and request.user
            and request.user.is_authenticated
        ) or (
            request.user and request.user.is_staff
        )


class IsAuthenticatedOrAdminForOrders(BasePermission):
    """
    Admin -> full access
    Authenticated user -> list and create
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_staff:
            return True
        if request.user and request.user.is_authenticated:
            if view.action in ["list", "create"]:
                return True
        return False
