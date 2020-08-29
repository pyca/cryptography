from django.test import TestCase
from django.http import HttpRequest
from django.template import Template, Context, TemplateSyntaxError

from text.templatetags.text import set_default, set_type, register_node, get_placeholder
from .utils import override_conf


load_statement = "{% load text %}"


def get_context():
        return Context({'request': HttpRequest()})


class TestTextTag(TestCase):
    @override_conf(TOOLBAR_INSTANT_UPDATE=False)
    def test_variable(self):
        context = get_context()
        node_name = 'a_node'
        default_text = 'some default content :)'
        node_type = "html"
        template = Template(load_statement + """\
{%% with t="%s" %%}{%% text "%s" t "%s" %%}{%% endwith %%}""" % (default_text, node_name, node_type))
        output = template.render(context)
        self.assertEqual(output, '{{ text_placeholder_%s }}' % node_name)
        self.assertEqual(context['request'].text_default_register[node_name], default_text)
        self.assertEqual(context['request'].text_type_register[node_name], node_type)
        self.assertIn(node_name, context['request'].text_register)

    @override_conf(TOOLBAR_INSTANT_UPDATE=True)
    def test_with_instant_update(self):
        context = get_context()
        node_name = 'a_node'
        default_text = 'some default content :)'
        node_type = "html"
        template = Template(load_statement + """\
{%% with t="%s" %%}{%% text "%s" t "%s" %%}{%% endwith %%}""" % (default_text, node_name, node_type))
        output = template.render(context)
        expected = """\
<span data-text-name="a_node" class="dj_text_inline_wrapper">{{ text_placeholde\
r_%s }}</span>""" % node_name
        self.assertEqual(output, expected)
        self.assertEqual(context['request'].text_default_register[node_name], default_text)
        self.assertEqual(context['request'].text_type_register[node_name], node_type)
        self.assertIn(node_name, context['request'].text_register)

    @override_conf(TOOLBAR_INSTANT_UPDATE=False)
    def test_without_node_type(self):
        context = get_context()
        node_name = 'a_node'
        default_text = 'this is my default text'
        template = Template(load_statement + '{%% text "%s" "%s" %%}' % (node_name, default_text))
        output = template.render(context)
        self.assertEqual(output, '{{ text_placeholder_%s }}' % node_name)
        self.assertEqual(context['request'].text_default_register[node_name], default_text)
        self.assertEqual(context['request'].text_type_register[node_name], "text")
        self.assertIn(node_name, context['request'].text_register)

    def test_syntax_errors(self):
        statements = [
            '{% text %}',
            '{% text "gotta have a default" %}',
            '{% text use "quotes" %}',
            '{% text "srsly" tho %}',
            '{% text "cant have a " "weird text type, like" "nonsense" %}',
            '{% text "too" "many" "arguments" "is not cool" "fo sho" %}',
        ]
        for statement in statements:
            with self.assertRaises(TemplateSyntaxError, msg=statement):
                Template(load_statement + statement).render(get_context())


class TestBlockTextTag(TestCase):
    @override_conf(TOOLBAR_INSTANT_UPDATE=False)
    def test_without_node_type(self):
        context = get_context()
        node_name = 'a_node'
        default_text = '<b>some</b> default content :)'
        node_type = "html"
        template = Template(load_statement + """\
{%% blocktext "%s" %%}%s{%% endblocktext %%}""" % (node_name, default_text))
        output = template.render(context)
        self.assertEqual(output, '{{ text_placeholder_%s }}' % node_name)
        self.assertEqual(context['request'].text_default_register[node_name], default_text)
        self.assertEqual(context['request'].text_type_register[node_name], node_type)
        self.assertIn(node_name, context['request'].text_register)

    @override_conf(TOOLBAR_INSTANT_UPDATE=True)
    def test_with_node_type(self):
        context = get_context()
        node_name = 'a_node'
        default_text = '<b>some</b> default content :)'
        node_type = "text"
        template = Template(load_statement + """\
{%% blocktext "%s" node_type="%s" instant_update=False %%}%s{%% endblocktext %%}""" % (
            node_name, node_type, default_text))
        output = template.render(context)
        self.assertEqual(output, '{{ text_placeholder_%s }}' % node_name)
        self.assertEqual(context['request'].text_default_register[node_name], default_text)
        self.assertEqual(context['request'].text_type_register[node_name], node_type)
        self.assertIn(node_name, context['request'].text_register)

    def test_syntax_errors(self):
        statements = [
            '{% blocktext %}{% endblocktext %}',
            '{% blocktext "lol" %}',
            '{% blocktext use_quotes %}{% endblocktext %}',
            '{% blocktext "use_quotes" html %}{% endblocktext %}',
            '{% blocktext "come on, learn the types" html5 %}{% endblocktext %}',
            '{% blocktext "too" "many" "arguments" "is not cool" %}{% endblocktext %}',
        ]
        for statement in statements:
            with self.assertRaises(TemplateSyntaxError, msg=statement):
                Template(load_statement + statement).render(get_context())


class TestGetPlaceholder(TestCase):
    @override_conf(TOOLBAR_INSTANT_UPDATE=True)
    def test_get_wrapped_placeholder(self):
        name = 'name_of_text_node'
        placeholder = get_placeholder(name, True)
        expected = """\
<span data-text-name="name_of_text_node" class="dj_text_inline_wrapper">\
{{ text_placeholder_name_of_text_node }}</span>"""
        self.assertEqual(placeholder, expected)

    @override_conf(TOOLBAR_INSTANT_UPDATE=False)
    def test_get_placeholder(self):
        name = 'name_of_text_node'
        placeholder = get_placeholder(name, True)
        expected = '{{ text_placeholder_name_of_text_node }}'
        self.assertEqual(placeholder, expected)


class TestSetDefault(TestCase):
    def test_set_default(self):
        name = 'name_of_text_node'
        content = 'test node content'
        context = {'request': HttpRequest()}
        set_default(name, context, content)
        self.assertEqual(context['request'].text_default_register[name], content)


class TestSetType(TestCase):
    def test_set_type(self):
        name = 'name_of_text_node'
        node_type = 'html'
        context = {'request': HttpRequest()}
        set_type(name, context, node_type)
        self.assertEqual(context['request'].text_type_register[name], node_type)


class TestRegister(TestCase):
    def test_register(self):
        name = 'name_of_text_node'
        context = {'request': HttpRequest()}
        register_node(name, context)
        self.assertIn(name, context['request'].text_register)
