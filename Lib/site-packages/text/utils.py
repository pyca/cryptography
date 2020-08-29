from .conf import settings


def can_access_toolbar(request):
    if not settings.TOOLBAR_ENABLED:
        return False
    user = getattr(request, 'user', None)
    return (user and user.is_authenticated() and user.is_active and
            user.is_staff and user.has_perm('text.change_text'))
