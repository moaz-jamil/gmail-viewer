# Generated by Django 5.1.6 on 2025-07-08 05:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gmail_app', '0007_delete_taggedemail'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailReply',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_id', models.CharField(max_length=255)),
                ('sender', models.EmailField(max_length=254)),
                ('body', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
