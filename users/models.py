from email.policy import default
from tabnanny import verbose
from tkinter import CASCADE
from django.db import models
from datetime import datetime
from django.utils import timezone
from django.core.validators import FileExtensionValidator
from django.contrib.auth.models import User

now = timezone.now()

class ComplaintType(models.Model):
    complaint_type = models.CharField(max_length=200, verbose_name='Complaint Type')
    creation_date = models.DateField(default=now, verbose_name='Created')
    updation_date = models.DateField(default=now, verbose_name='Last Updated')
    
    def __str__(self):
        return self.complaint_type
    


    

    
class TbleComplaint(models.Model):
    complainant = models.ForeignKey(User, on_delete=models.CASCADE)
    complaintType = models.ForeignKey(ComplaintType, default=True, on_delete=models.CASCADE, related_name='complaints')
    complaint_addr = models.CharField(max_length=250, verbose_name='Complaint Address')
    complaint_details = models.CharField(max_length=250, verbose_name='Complaint Details')
    complaint_file = models.FileField(upload_to='media', validators=[FileExtensionValidator(allowed_extensions=['pdf', 'docx', 'doc', 'png', 'jpg', 'jpeg', 'mp4', 'mkv', 'mp3', 'ppt'])], verbose_name='Complaint Files')
    complaintStatus = models.CharField(max_length=20, verbose_name="Complaint Status")
    complaint_remark = models.CharField(max_length=1000, blank=True, verbose_name='remark')
    complaint_regDate = models.DateField(default=now, verbose_name='Complaint Submitted Date')
    
    def __str__(self):
        return self.complaint_details
        
    
    
class SystemAdmin(models.Model):
    username = models.CharField(max_length=250, verbose_name='Admin Username')
    password = models.CharField(max_length=250, verbose_name='Admin Password')
    

class Profile(models.Model):
    user = models.OneToOneField(User , on_delete=models.CASCADE)
    forget_password_token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username