from functools import partial

from django.conf import settings as django_settings

s = partial(getattr, django_settings)


class Conf(object):
    AUTOPOPULATE_TEXT = s('AUTOPOPULATE_TEXT', True)
    TOOLBAR_FORM_PREFIX = s('TEXT_TOOLBAR_FORM_PREFIX', 'djtext_form')
    TOOLBAR_ENABLED = s('TEXT_TOOLBAR_ENABLED', True)
    TOOLBAR_INSTANT_UPDATE = s('TEXT_TOOLBAR_INSTANT_UPDATE', True)
    INLINE_WRAPPER = s('TEXT_INLINE_WRAPPER', ('<span data-text-name="{0}" class="{1}">', '</span>'))
    INLINE_WRAPPER_CLASS = s('TEXT_INLINE_WRAPPER_CLASS', 'dj_text_inline_wrapper')

settings = Conf()
