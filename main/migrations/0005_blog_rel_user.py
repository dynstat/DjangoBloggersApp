# Generated by Django 4.2.1 on 2023-05-27 15:04

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0004_blog"),
    ]

    operations = [
        migrations.AddField(
            model_name="blog",
            name="rel_user",
            field=models.ForeignKey(
                default="", on_delete=django.db.models.deletion.CASCADE, to="main.user"
            ),
            preserve_default=False,
        ),
    ]
