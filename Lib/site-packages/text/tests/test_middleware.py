from django.test import TestCase
from django.http import HttpRequest
from django.template.base import Context, Template
from django.template.response import SimpleTemplateResponse
from django.utils.six import b
from django.utils.encoding import force_text
from django.contrib.auth.models import User

from mock import patch

from ..compat import BackendTemplate
from ..middleware import (
    build_context, create_text, TextMiddleware, ToolbarMiddleware)
from ..models import Text
from ..conf import settings


class TestBuildContext(TestCase):
    def test_use_default(self):
        texts = []
        defaults = {'a_text_node': '<p>wooot</p>'}
        types = {'a_text_node': 'html'}
        c = build_context(texts, defaults, types)
        # test return value
        self.assertEqual(c['text_placeholder_a_text_node'], defaults['a_text_node'])
        # test model integration
        t = Text.objects.get(name='a_text_node')
        self.assertEqual(t.render(), defaults['a_text_node'])
        self.assertEqual(t.type, types['a_text_node'])

    @patch('text.middleware.create_text')
    def test_use_db(self, create_text):
        t = Text(name='my_text_node', type='markdown', body='# Hello')
        t.save()
        texts = [t]
        defaults = {'my_text_node': '<p>LOL</p>'}
        types = {'my_text_node': 'markdown'}
        c = build_context(texts, defaults, types)
        self.assertFalse(create_text.called)
        self.assertEqual(c['text_placeholder_my_text_node'], t.render())


class TestCreateText(TestCase):
    def test_use_default_type(self):
        name = 'my_text'
        body = 'my text is so awesome'
        t = create_text(name, body, None)
        self.assertEqual(t.type, Text.TYPE_TEXT)

    def test_save(self):
        name = 'my_text'
        body = 'my text is so awesome'
        text_type = 'html'
        settings.AUTOPOPULATE_TEXT = True
        t = create_text(name, body, text_type)
        tdb = Text.objects.get(name=name)
        self.assertEqual(t.type, text_type)
        self.assertEqual(tdb.type, text_type)
        self.assertEqual(t.name, name)
        self.assertEqual(tdb.name, name)
        self.assertEqual(t.body, body)
        self.assertEqual(tdb.body, body)

    def test_no_autopopulate(self):
        settings.AUTOPOPULATE_TEXT = False
        create_text('a_name', 'a body', Text.TYPE_HTML)
        self.assertEqual(Text.objects.count(), 0)


class TestTextMiddleware(TestCase):
    tag_template = '{%% load text %%}{%% text "%s" "%s" %%}'

    def process_template_response(self, string_template):
        settings.TOOLBAR_INSTANT_UPDATE = False
        request = HttpRequest()
        context = Context({'request': request})
        node = Template(string_template).render(context)
        template = BackendTemplate(node)
        response = SimpleTemplateResponse(template, context)
        response.content = node
        mw = TextMiddleware()
        return mw.process_response(request, response).render()

    def test_default(self):
        content = "some test content"
        template = self.tag_template % ('node', content)
        rendered = self.process_template_response(template)
        self.assertEqual(rendered.content, b(content))

    def test_db(self):
        text = Text(name='db_node', body='my awesome text', type=Text.TYPE_TEXT)
        text.save()
        template = self.tag_template % (text.name, 'this is the default')
        rendered = self.process_template_response(template)
        self.assertEqual(rendered.content, b(text.render()))

    def test_no_tags(self):
        rendered = self.process_template_response('')
        self.assertEqual(rendered.content, b(''))


class TestToolbarMiddleware(TestCase):
    text_template = (
        '<body>{% load text %}{% text "a_node" "html" %}</body>')
    non_text_template = '<body></body>'
    invalid_text_template = '{% load text %}{% text "a_node" "html" %}'

    def process_template_response(self, string_template, user=None):
        request = HttpRequest()
        request.user = user
        context = Context({'request': request})
        template = BackendTemplate(Template(string_template).render(context))
        response = SimpleTemplateResponse(template, context)
        response.content = string_template
        mw = ToolbarMiddleware()
        return mw.process_response(request, response).render()

    def test_process_response(self):
        su = User.objects.create_superuser('adm', 'adm@example.com', 'pw')

        # unauthenticated
        resp = self.process_template_response(self.text_template)
        self.assertNotIn(
            'djtext_toolbar', force_text(resp.content, encoding='utf-8'))

        # authenticated, no texts
        resp = self.process_template_response(self.non_text_template, su)
        self.assertNotIn(
            'djtext_toolbar', force_text(resp.content, encoding='utf-8'))

        # authenticated, no closing body tag
        resp = self.process_template_response(self.invalid_text_template, su)
        self.assertNotIn(
            'djtext_toolbar', force_text(resp.content, encoding='utf-8'))

        # authenticated
        resp = self.process_template_response(self.text_template, su)
        self.assertIn(
            'djtext_toolbar', force_text(resp.content, encoding='utf-8'))
