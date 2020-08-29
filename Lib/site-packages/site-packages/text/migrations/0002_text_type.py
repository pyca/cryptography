# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='text',
            name='type',
            field=models.IntegerField(default=0, choices=[(0, b'Text'), (1, b'Markdown')]),
            preserve_default=True,
        ),
    ]
