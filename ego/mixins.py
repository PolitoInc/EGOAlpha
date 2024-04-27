from django.http import HttpResponseForbidden
from .models import UserProfile

class RoleRequiredMixin:
    """Mixin for views that checks that the user has a specific role."""
    roles_required = None

    def dispatch(self, request, *args, **kwargs):
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role in self.roles_required:
            return super().dispatch(request, *args, **kwargs)
        else:
            return HttpResponseForbidden("You do not have permission to perform this action.")