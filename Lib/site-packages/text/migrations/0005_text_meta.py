# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0004_text_default_type'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='text',
            options={'ordering': ('name', 'language')},
        ),
    ]
