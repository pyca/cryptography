from django.test import TestCase
from django.http import HttpRequest

from ..conf import settings
from ..utils import can_access_toolbar


class TestAccessToolbar(TestCase):
    def test(self):
        class User(object):
            is_active = True
            is_staff = True

            def is_authenticated(self):
                return True

            def has_perm(self, perm):
                return True

        class InActiveUser(User):
            is_active = False

        class NotStaffUser(User):
            is_staff = False

        class NotAuthenticatedUser(User):
            def is_authenticated(self):
                return False

        class NoPermUser(User):
            def has_perm(self, perm):
                return False

        req = HttpRequest()
        req.user = User()

        settings.TOOLBAR_ENABLED = False
        self.assertFalse(can_access_toolbar(req))
        settings.TOOLBAR_ENABLED = True
        self.assertTrue(can_access_toolbar(req))
        req.user = InActiveUser()
        self.assertFalse(can_access_toolbar(req))
        req.user = NotStaffUser()
        self.assertFalse(can_access_toolbar(req))
        req.user = NotAuthenticatedUser()
        self.assertFalse(can_access_toolbar(req))
        req.user = NoPermUser()
        self.assertFalse(can_access_toolbar(req))
