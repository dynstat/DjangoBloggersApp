# Generated by Django 4.2.1 on 2023-06-11 15:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0010_remove_user_email_verification"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="email_verification",
            field=models.BooleanField(default=0),
        ),
    ]
