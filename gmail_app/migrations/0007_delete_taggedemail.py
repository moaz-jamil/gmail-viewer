# Generated by Django 5.1.6 on 2025-07-08 05:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('gmail_app', '0006_taggedemail'),
    ]

    operations = [
        migrations.DeleteModel(
            name='TaggedEmail',
        ),
    ]
