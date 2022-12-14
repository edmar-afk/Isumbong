# Generated by Django 4.0.5 on 2022-10-05 10:27

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_alter_complaintremark_remark_date_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='user_email',
            new_name='email',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='user_fname',
            new_name='fname',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='user_mobile',
            new_name='mobile',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='user_password',
            new_name='password',
        ),
        migrations.RemoveField(
            model_name='user',
            name='user_regDate',
        ),
        migrations.AddField(
            model_name='user',
            name='regDate',
            field=models.DateField(default=datetime.datetime(2022, 10, 5, 10, 27, 7, 224139, tzinfo=utc), verbose_name='Registered Date'),
        ),
        migrations.AlterField(
            model_name='complaintremark',
            name='remark_date',
            field=models.DateField(default=datetime.datetime(2022, 10, 5, 10, 27, 7, 224139, tzinfo=utc), verbose_name='Remark Date'),
        ),
        migrations.AlterField(
            model_name='complainttype',
            name='creation_date',
            field=models.DateField(default=datetime.datetime(2022, 10, 5, 10, 27, 7, 224139, tzinfo=utc), verbose_name='Created'),
        ),
        migrations.AlterField(
            model_name='complainttype',
            name='updation_date',
            field=models.DateField(default=datetime.datetime(2022, 10, 5, 10, 27, 7, 224139, tzinfo=utc), verbose_name='Last Updated'),
        ),
        migrations.AlterField(
            model_name='tblecomplaint',
            name='complaint_regDate',
            field=models.DateField(default=datetime.datetime(2022, 10, 5, 10, 27, 7, 224139, tzinfo=utc), verbose_name='Complaint Submitted Date'),
        ),
    ]
