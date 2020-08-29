from functools import partial

from django import VERSION
from django.template.backends.django import Template as DjangoBackendTemplate, DjangoTemplates
from django.template import Template, RequestContext, Context


# Handle backend argument introduced in Django 1.9
if VERSION[1] < 9:
    BackendTemplate = DjangoBackendTemplate
else:
    BackendTemplate = partial(DjangoBackendTemplate, backend=DjangoTemplates)


def render_template(template, context=None, request=None):
    if isinstance(template, Template):
        if request:
            context = RequestContext(request, context)
        else:
            context = Context(context)
        return template.render(context)
    else:
        return template.render(context, request=request)
