# Generated by Django 4.1.3 on 2022-12-04 14:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_user_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='otp_end_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
