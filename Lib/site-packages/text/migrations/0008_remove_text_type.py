# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('text', '0007_type_int_to_char'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='text',
            name='type',
        ),
    ]
