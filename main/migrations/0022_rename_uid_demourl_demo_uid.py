# Generated by Django 4.2.1 on 2023-06-17 08:02

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0021_demourl_rel_blog"),
    ]

    operations = [
        migrations.RenameField(
            model_name="demourl",
            old_name="uid",
            new_name="demo_uid",
        ),
    ]
