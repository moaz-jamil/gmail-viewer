# Generated by Django 5.1.6 on 2025-07-06 07:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('gmail_app', '0004_taggedemail_delete_emailtag'),
    ]

    operations = [
        migrations.DeleteModel(
            name='TaggedEmail',
        ),
    ]
