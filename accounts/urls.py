from django.urls import path

from . import views
from .views import login_view, register_view, logout_view, dashboard, delete_user,add_user

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("register/", views.register_view, name="register"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("manage_users/", views.manage_users, name="manage_users"),  # ✅ Ensure this exists
    path("edit_user/<int:user_id>/", views.edit_user, name="edit_user"),  # ✅ Fix the missing edit_user URL
    path('delete_user/<int:user_id>/', delete_user, name='delete_user'),
    path('add_user/', add_user, name='add_user'),
    path("access_denied/", views.access_denied, name="access_denied"),  # ✅ Ensure this URL exists
]
