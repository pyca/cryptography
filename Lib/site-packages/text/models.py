from django.db import models
from django.conf import settings
from django.utils.safestring import mark_safe

import markdown


class Text(models.Model):
    TYPE_TEXT = 'text'
    TYPE_MARKDOWN = 'markdown'
    TYPE_HTML = 'html'
    TYPES = (
        (TYPE_TEXT, 'Text'),
        (TYPE_MARKDOWN, 'Markdown'),
        (TYPE_HTML, 'HTML'),
    )

    name = models.CharField(max_length=50, db_index=True)
    body = models.TextField()
    type = models.CharField(
        choices=TYPES,
        blank=False,
        default=TYPE_TEXT,
        max_length=20)
    language = models.CharField(
        choices=settings.LANGUAGES,
        max_length=5,
        default=settings.LANGUAGE_CODE)

    class Meta:
        unique_together = ('name', 'language', )
        index_together = ['name', 'language', ]
        ordering = ('name', 'language', )

    def __unicode__(self):
        return self.text_id

    def __str__(self):
        return self.__unicode__()

    def render_markdown(self, text):
        return markdown.markdown(text, output_format='html5')

    def render_html(self, text):
        return text

    def render_text(self, text):
        return text

    def render(self):
        render = getattr(self, 'render_{0}'.format(self.type))
        return mark_safe(render(self.body))

    @property
    def text_id(self):
        return "%s_%s" % (self.name, self.language)
