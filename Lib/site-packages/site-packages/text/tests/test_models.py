from django.test import TestCase

from text.models import Text


class TestText(TestCase):
    def test_render(self):
        t = Text(body='# hello', type=Text.TYPE_MARKDOWN)
        self.assertEqual(t.render(), '<h1>hello</h1>')
        t = Text(body='# hello')
        self.assertEqual(t.render(), '# hello')

    def test_text_id(self):
        t = Text(name='hello', language='sv')
        self.assertEqual(t.text_id, 'hello_sv')
        self.assertEqual(t.text_id, str(t))
