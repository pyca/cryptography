# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0008_remove_text_type'),
    ]

    operations = [
        migrations.RenameField(
            model_name='text',
            old_name='type_char',
            new_name='type',
        ),
    ]
