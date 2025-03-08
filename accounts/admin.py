from django.contrib import admin
from .models import CustomUser

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'is_active', 'date_joined')
    search_fields = ['username', 'email']
    list_filter = ['role']
  # Prevent manual edits

admin.site.register(CustomUser, CustomUserAdmin)
