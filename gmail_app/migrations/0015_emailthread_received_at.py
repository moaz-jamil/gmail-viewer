# Generated by Django 5.1.6 on 2025-07-10 06:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gmail_app', '0014_remove_emailreply_thread_id_emailreply_thread_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='emailthread',
            name='received_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
