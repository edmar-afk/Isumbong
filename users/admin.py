from django.contrib import admin
from .models import ComplaintType, TbleComplaint, SystemAdmin

# Register your models here.

admin.site.site_header = 'E - sumbong'
admin.site.site_title = 'LGU Guipos'

class UserAdmin(admin.ModelAdmin):
    list_display = ['user_fname', 'user_email', 'user_regDate', 'user_mobile']
    search_fields = ['user_fname', 'user_email', 'user_regDate', 'user_mobile']
   

class ComplaintTypeAdmin(admin.ModelAdmin):
    list_display = ['id', 'complaint_type', 'creation_date', 'updation_date']
    search_fields = ['id', 'complaint_type', 'creation_date', 'updation_date']
 


class TbleComplaintAdmin(admin.ModelAdmin):
    list_display = ['id','complainant_id', 'complaintType_id', 'complaint_addr', 'complaint_details', 'complaint_file', 'complaintStatus', 'complaint_remark', 'complaint_regDate']
    search_fields = ['id','complainant_id', 'complaintType_id', 'complaint_addr', 'complaint_details','complaint_file', 'complaintStatus', 'complaint_remark','complaint_regDate']


class AdminSystem(admin.ModelAdmin):
     list_display = ['username', 'password']
     search_fields = ['username', 'password']
    
admin.site.register(ComplaintType, ComplaintTypeAdmin)
admin.site.register(TbleComplaint, TbleComplaintAdmin)
admin.site.register(SystemAdmin, AdminSystem)
