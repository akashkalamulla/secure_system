from django.contrib import admin
from django.urls import path, include
from accounts.views import home  # ✅ Import home view

urlpatterns = [
    path("", home, name="home"),  # ✅ Home Page URL
    path("admin/", admin.site.urls),  # ✅ Admin Panel
    path("accounts/", include("accounts.urls")),  # ✅ User Authentication URLs
]
