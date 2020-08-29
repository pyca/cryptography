# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0002_text_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='text',
            name='language',
            field=models.CharField(default=settings.LANGUAGE_CODE, max_length=5, choices=settings.LANGUAGES),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='text',
            name='name',
            field=models.CharField(max_length=50, db_index=True),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='text',
            unique_together=set([('name', 'language')]),
        ),
        migrations.AlterIndexTogether(
            name='text',
            index_together=set([('name', 'language')]),
        ),
    ]
