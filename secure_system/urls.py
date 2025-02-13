from django.contrib import admin
from django.urls import path, include

from accounts import views
from accounts.views import home  # ✅ Import home view

urlpatterns = [
    path("", home, name="home"),  # ✅ Home Page URL
    path("admin/", admin.site.urls),  # ✅ Admin Panel
    path("accounts/", include("accounts.urls")),  # ✅ User Authentication URLs
    path("admin_dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("manage_users/", views.manage_users, name="manage_users"),
    path("view_logs/", views.view_logs, name="view_logs"),
]
