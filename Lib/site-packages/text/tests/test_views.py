from django.test import TestCase, RequestFactory
from django.http import Http404
from django.contrib.auth.models import User

from text.views import Slug, TextView, TextUpdateView
from text.models import Text
from text.conf import settings


class TestTextView(TestCase):
    def setUp(self):
        self.request = RequestFactory().get('/text/a_text_node_en-us/')
        self.request.user = User.objects.create_user(
            'admin', 'admin@example.com', 'password')
        self.view = TextView.as_view()
        self.text = Text(
            name='a_text_node',
            body='hello',
            type=Text.TYPE_TEXT,
            language='en-us')
        self.text.save()

    def test_parse_slug(self):
        s = TextView.parse_slug('the_node_name_sv-se')
        self.assertIsInstance(s, Slug)
        self.assertEqual(s.language, 'sv-se')
        self.assertEqual(s.name, 'the_node_name')

        with self.assertRaises(Http404):
            TextView.parse_slug('the')

        with self.assertRaises(Http404):
            TextView.parse_slug(None)

    def test_get(self):
        with self.assertRaises(Http404):
            self.view(self.request)

        self.request.user.is_staff = True
        self.request.user.is_superuser = True

        with self.assertRaises(Http404):
            self.view(self.request, text_slug='nonsense_en-us')

        response = self.view(self.request, text_slug='a_text_node_en-us')
        self.assertEqual(response.status_code, 200)


class TestTextUpdateView(TestCase):
    def setUp(self):
        self.view = TextUpdateView.as_view()
        self.text = Text(
            name='a_text_node',
            body='hello',
            type=Text.TYPE_TEXT,
            language='en-us')
        self.text.save()
        self.request = RequestFactory().post(
            '/update_text/{0}/'.format(self.text.id))
        self.request.user = User.objects.create_user(
            'admin', 'admin@example.com', 'password')

    def test_get_form_kwargs(self):
        view = TextUpdateView()
        view.request = self.request
        kwargs = view.get_form_kwargs()
        self.assertEqual(kwargs['prefix'], settings.TOOLBAR_FORM_PREFIX)

    def test_post(self):
        with self.assertRaises(Http404):
            self.view(self.request)

        self.request.user.is_staff = True
        self.request.user.is_superuser = True
        resp = self.view(self.request, text_id=self.text.id)
        self.assertEqual(resp.status_code, 200)

        request = RequestFactory().post(
            '/update_text/{0}/'.format(self.text.id),
            data={
                settings.TOOLBAR_FORM_PREFIX + '-body': 'lol',
                settings.TOOLBAR_FORM_PREFIX + '-name': 'woot',
                settings.TOOLBAR_FORM_PREFIX + '-type': 'text',
            })
        request.user = User.objects.create_user(
            'admin1', 'admin@example.com', 'password')
        request.user.is_staff = True
        request.user.is_superuser = True
        resp = self.view(request, text_id=self.text.id)
        self.assertEqual(resp.status_code, 204)

        text = Text.objects.get(pk=self.text.pk)
        self.assertEqual(text.body, 'lol')
        self.assertEqual(text.name, 'woot')
        self.assertEqual(text.type, 'text')
