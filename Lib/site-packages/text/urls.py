from django.conf.urls import url

from .views import TextView, TextUpdateView

urlpatterns = [
    url(r'^text/(?P<text_slug>[\w-]+)/$', TextView.as_view(), name='text'),
    url(r'^update_text/(?P<text_id>\d+)/$', TextUpdateView.as_view(), name='update_text'),
]
