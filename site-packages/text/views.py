from collections import namedtuple

from django.http import JsonResponse, Http404, HttpResponse
from django.views.generic import DetailView, UpdateView

from .models import Text
from .forms import TextForm
from .conf import settings
from .utils import can_access_toolbar

Slug = namedtuple('Slug', 'language, name')


class TextView(DetailView):
    missing_node_exc = Http404("Found no text with that id")
    model = Text

    @staticmethod
    def parse_slug(slug):
        if slug is None:
            raise TextView.missing_node_exc
        parts = slug.split('_')
        if len(parts) < 2:
            raise TextView.missing_node_exc
        return Slug(language=parts[-1], name='_'.join(parts[:-1]))

    def get_object(self, queryset=None):
        slug = self.parse_slug(self.kwargs.get('text_slug', None))
        if queryset is None:
            queryset = self.get_queryset()
        queryset = queryset.filter(name=slug.name, language=slug.language)
        try:
            # Get the single item from the filtered queryset
            return queryset.get()
        except queryset.model.DoesNotExist:
            raise TextView.missing_node_exc

    def get(self, request, *args, **kwargs):
        if not can_access_toolbar(request):
            raise Http404()
        self.object = self.get_object()
        data = {
            'id': self.object.id,
            'body': self.object.body,
            'type': self.object.type,
            'language': self.object.language,
            'render': self.object.render(),
            'name': self.object.name,
        }
        return JsonResponse(data)


class TextUpdateView(UpdateView):
    model = Text
    form_class = TextForm
    pk_url_kwarg = 'text_id'
    form_prefix = settings.TOOLBAR_FORM_PREFIX

    def get_form_kwargs(self):
        kwargs = super(TextUpdateView, self).get_form_kwargs()
        if self.form_prefix:
            kwargs.update({'prefix': self.form_prefix})
        return kwargs

    def post(self, request, *args, **kwargs):
        if not can_access_toolbar(request):
            raise Http404()
        self.object = self.get_object()
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            self.object = form.save()
            return HttpResponse(status=204)
        else:
            return JsonResponse({'errors': form.errors, 'success': False})
