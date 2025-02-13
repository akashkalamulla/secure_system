from django.contrib import admin
from .models import CustomUser

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ("username", "admin_id", "employee_id", "role")
    readonly_fields = ("admin_id", "employee_id")  # Prevent manual edits

admin.site.register(CustomUser, CustomUserAdmin)
