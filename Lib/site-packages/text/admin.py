from django.contrib import admin
from django.db import models

from .models import Text
from .widgets import HTMLEditorWidget


class TextAdmin(admin.ModelAdmin):
    list_display = ('name', 'language', 'type', )
    search_fields = ('name', )
    formfield_overrides = {
        models.TextField: {'widget': HTMLEditorWidget},
    }


admin.site.register(Text, TextAdmin)
