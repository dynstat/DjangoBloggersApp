# Generated by Django 4.2.1 on 2023-06-14 14:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0018_alter_published_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="published",
            name="id",
            field=models.AutoField(default=1, primary_key=True, serialize=False),
        ),
    ]
