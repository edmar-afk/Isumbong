# Generated by Django 4.0.5 on 2022-10-08 02:47

import datetime
from django.db import migrations, models
import django.db.models.deletion
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0016_alter_complaintremark_remark_date_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tblecomplaint',
            name='complaintRemark',
        ),
        migrations.AddField(
            model_name='tblecomplaint',
            name='complaint_remark',
            field=models.CharField(blank=True, max_length=1000, verbose_name='remark'),
        ),
        migrations.AlterField(
            model_name='complainttype',
            name='creation_date',
            field=models.DateField(default=datetime.datetime(2022, 10, 8, 2, 47, 45, 548302, tzinfo=utc), verbose_name='Created'),
        ),
        migrations.AlterField(
            model_name='complainttype',
            name='updation_date',
            field=models.DateField(default=datetime.datetime(2022, 10, 8, 2, 47, 45, 548302, tzinfo=utc), verbose_name='Last Updated'),
        ),
        migrations.AlterField(
            model_name='tblecomplaint',
            name='complaintStatus',
            field=models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, related_name='status', to='users.complaintstatus'),
        ),
        migrations.AlterField(
            model_name='tblecomplaint',
            name='complaint_regDate',
            field=models.DateField(default=datetime.datetime(2022, 10, 8, 2, 47, 45, 548302, tzinfo=utc), verbose_name='Complaint Submitted Date'),
        ),
        migrations.AlterField(
            model_name='user',
            name='user_regDate',
            field=models.DateField(default=datetime.datetime(2022, 10, 8, 2, 47, 45, 548302, tzinfo=utc), verbose_name='Registered Date'),
        ),
        migrations.DeleteModel(
            name='ComplaintRemark',
        ),
    ]
