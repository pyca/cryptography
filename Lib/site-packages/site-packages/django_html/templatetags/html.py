"""
{% doctype "html4" %}
{% doctype "html4" silent %} # set internal doctype but do NOT output it
{% doctype "html4trans" %}
{% doctype "html5" %}
{% doctype "xhtml1" %}
{% doctype "xhtml1trans" %}

{% field form.name %} # Outputs correct widget based on current doctype
{% field form.name class="my-form-class" %} # Adds an attribute
"""
import re

doctypes = {
  'html4': """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
    "http://www.w3.org/TR/html4/strict.dtd">""",
  'html4trans': """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
    "http://www.w3.org/TR/html4/loose.dtd">""",
  'xhtml1': """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">""",
  'xhtml1trans': """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">""",
  'html5': '<!DOCTYPE html>',
}
html_doctypes = ('html4', 'html5', 'html4trans')

from django import template
register = template.Library()

def do_doctype(parser, token):
    bits = token.split_contents()
    if len(bits) not in (2, 3):
        raise template.TemplateSyntaxError, \
            "%r tag requires 1-2 arguments" % bits[0]
    if len(bits) == 3 and bits[2] != 'silent':
        raise template.TemplateSyntaxError, \
            "If provided, %r tag second argument must be 'silent'" % bits[0]
    # If doctype is wrapped in quotes, they should balance
    doctype = bits[1]
    if doctype[0] in ('"', "'") and doctype[-1] != doctype[0]:
        raise template.TemplateSyntaxError, \
            "%r tag quotes need to balance" % bits[0]
    return DoctypeNode(bits[1], is_silent = (len(bits) == 3))

class DoctypeNode(template.Node):
    def __init__(self, doctype, is_silent=False):
        self.doctype = doctype
        self.is_silent = is_silent
    
    def render(self, context):
        if self.doctype[0] in ('"', "'"):
            doctype = self.doctype[1:-1]
        else:
            try:
                doctype = template.resolve_variable(self.doctype, context)
            except template.VariableDoesNotExist:
                # Cheeky! Assume that they typed a doctype without quotes
                doctype = self.doctype
        # Set doctype in the context
        context._doctype = doctype
        if self.is_silent:
            return ''
        else:
            return doctypes.get(doctype, '')

register.tag('doctype', do_doctype)

xhtml_end_re = re.compile('\s*/>')

class FieldNode(template.Node):
    def __init__(self, field_var, extra_attrs):
        self.field_var = field_var
        self.extra_attrs = extra_attrs
    
    def render(self, context):
        field = template.resolve_variable(self.field_var, context)
        # Caling bound_field.as_widget() returns the HTML, but we need to 
        # intercept this to manipulate the attributes - so we have to 
        # duplicate the logic from as_widget here.
        widget = field.field.widget
        attrs = self.extra_attrs or {}
        auto_id = field.auto_id
        if auto_id and 'id' not in attrs and 'id' not in widget.attrs:
            attrs['id'] = auto_id
        if not field.form.is_bound:
            data = field.form.initial.get(field.name, field.field.initial)
            if callable(data):
                data = data()
        else:
            data = field.data
        html = widget.render(field.html_name, data, attrs=attrs)
        # Finally, if we're NOT in xhtml mode ensure no '/>'
        doctype = getattr(context, '_doctype', 'xhtml1')
        if doctype in html_doctypes:
            html = xhtml_end_re.sub('>', html)
        return html

def do_field(parser, token):
    # Can't use split_contents here as we need to process 'class="foo"' etc
    bits = token.contents.split()
    if len(bits) == 1:
        raise template.TemplateSyntaxError, \
            "%r tag takes arguments" % bits[0]
    field_var = bits[1]
    extra_attrs = {}
    if len(bits) > 1:
        # There are extra name="value" arguments to consume
        extra_attrs = parse_extra_attrs(' '.join(bits[2:]))
    return FieldNode(field_var, extra_attrs)

register.tag('field', do_field)

class SlashNode(template.Node):
    def render(self, context):
        doctype = getattr(context, '_doctype', 'xhtml1')
        if doctype in html_doctypes:
            return ''
        else:
            return ' /'

def do_slash(parser, token):
    bits = token.contents.split()
    if len(bits) != 1:
        raise template.TemplateSyntaxError, \
            "%r tag takes no arguments" % bits[0]
    return SlashNode()

register.tag('slash', do_slash)

extra_attrs_re = re.compile(r'''([a-zA-Z][0-9a-zA-Z_-]*)="(.*?)"\s*''')

def parse_extra_attrs(contents):
    """
    Input should be 'foo="bar" baz="bat"' - output is corresponding dict. 
    Raises TemplateSyntaxError if something is wrong with the input.
    """
    unwanted = extra_attrs_re.sub('', contents)
    if unwanted.strip():
        raise template.TemplateSyntaxError, \
            "Invalid field tag arguments: '%s'" % unwanted.strip()
    return dict(extra_attrs_re.findall(contents))
