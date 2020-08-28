# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0003_text_language'),
    ]

    operations = [
        migrations.AlterField(
            model_name='text',
            name='type',
            field=models.IntegerField(default=1, choices=[(0, b'Text'), (1, b'Markdown')]),
            preserve_default=True,
        ),
    ]
