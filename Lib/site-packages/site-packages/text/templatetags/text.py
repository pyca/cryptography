from django import template
from django.utils.safestring import SafeData, mark_safe

from ..vendor.simple_block_tag import simple_block_tag
from ..conf import settings
from ..models import Text

register = template.Library()
TEXT_TYPES = [t[0] for t in Text.TYPES]


def get_placeholder(node_name, instant_update):
    placeholder = "{{ text_placeholder_%s }}"
    if instant_update and settings.TOOLBAR_INSTANT_UPDATE:
        before, after = settings.INLINE_WRAPPER
        before = before.format(node_name, settings.INLINE_WRAPPER_CLASS)
        placeholder = ''.join((before, placeholder, after))
    return mark_safe(placeholder % node_name)


def set_default(node_name, context, content):
    if not hasattr(context['request'], 'text_default_register'):
        context['request'].text_default_register = {}
    context['request'].text_default_register[node_name] = content.strip()


def set_type(node_name, context, text_type):
    if not hasattr(context['request'], 'text_type_register'):
        context['request'].text_type_register = {}
    context['request'].text_type_register[node_name] = text_type


def register_node(node_name, context):
    if not hasattr(context['request'], 'text_register'):
        context['request'].text_register = []
    context['request'].text_register.append(node_name)


def valid_type(type):
    return type in TEXT_TYPES


def is_safestring(var):
    return isinstance(var, SafeData)


@register.simple_tag(name='text', takes_context=True)
def text(context, node_name, default_text, node_type='text', instant_update=True):
    """
    Syntax:
        {% text <node_name> <default_text> <node_type> <instant_update> %}
    """
    if not is_safestring(node_name) or not is_safestring(default_text):
        raise template.TemplateSyntaxError("`node_name` and `default_text` need to be quoted strings")
    if not valid_type(node_type):
        raise template.TemplateSyntaxError("`node_type` has to be one of %s" % (', '.join(TEXT_TYPES)))
    register_node(node_name, context)
    set_default(node_name, context, default_text)
    set_type(node_name, context, node_type)
    return get_placeholder(node_name, bool(instant_update))


@simple_block_tag(register, name='blocktext', takes_context=True)
def blocktext(context, content, node_name, node_type='html', instant_update=True):
    """
    Syntax:
        {% blocktext <node_name> <node_type> <instant_update> %}<default_text>{% endblocktext %}
    """
    if not is_safestring(node_name):
        raise template.TemplateSyntaxError("`node_name` need to be a quoted string")
    if not valid_type(node_type):
        raise template.TemplateSyntaxError("`node_type` has to be one of %s" % (', '.join(TEXT_TYPES)))
    register_node(node_name, context)
    set_default(node_name, context, content)
    set_type(node_name, context, node_type)
    return get_placeholder(node_name, bool(instant_update))
