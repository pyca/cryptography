# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0005_text_meta'),
    ]

    operations = [
        migrations.AddField(
            model_name='text',
            name='type_char',
            field=models.CharField(default=b'markdown', max_length=20, choices=[(b'text', b'Text'), (b'markdown', b'Markdown')]),
            preserve_default=True,
        ),
    ]
