# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations


def populate_type_char(apps, schema_editor):
    Text = apps.get_model('text', 'Text')
    types = {
        0: b'text',
        1: b'markdown',
    }
    for text in Text.objects.all().iterator():
        text.type_char = types[text.type]
        text.save()


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0006_text_type_char'),
    ]

    operations = [
        migrations.RunPython(populate_type_char),
    ]
