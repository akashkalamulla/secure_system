import csv
import os
from urllib import request

from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect,get_object_or_404
from .forms import LoginForm, UserForm, FileUploadForm, TaskForm, NotificationForm
from django.contrib.auth import get_user_model, update_session_auth_hash
from accounts.models import CustomUser, UploadedFile, Task, Notification
from django_ratelimit.decorators import ratelimit
from axes.decorators import axes_dispatch
from django.views.decorators.csrf import csrf_exempt
from security.logs import log_failed_login
from django.contrib.auth.decorators import login_required, user_passes_test
from security.two_factor_auth import generate_otp, verify_otp
from django.contrib.auth import login, authenticate, logout
from .forms import RegisterForm,EditUserForm
from django.urls import reverse
from django.contrib.auth.hashers import make_password
from axes.utils import reset
from django.contrib import messages


# Get the custom user model
User = get_user_model()
def home(request):
    return render(request, "home.html")
def role_required(role):
    """
    Decorator to restrict access based on user role.
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated and request.user.role == role:
                return view_func(request, *args, **kwargs)
            return redirect("access_denied")
        return wrapper
    return decorator
@csrf_exempt
@axes_dispatch
@ratelimit(key="ip", rate="5/m", method="POST", block=True)
def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            if user.role == 'admin':
                return redirect('admin_dashboard')  # Admin-specific dashboard
            elif user.role == 'employee':
                return redirect('employee_dashboard')  # Employee-specific dashboard
            else:
                return redirect('guest_dashboard')  # Guest-specific dashboard
        else:
            messages.error(request, "Invalid credentials.")
            return render(request, "login.html")
    return render(request, "login.html")

@login_required
def two_factor_auth(request):
    """
    View to handle Two-Factor Authentication (2FA).
    """
    if request.method == "POST":
        otp = request.POST.get("otp")
        if verify_otp(request.user, otp):
            request.session["2fa_verified"] = True
            return redirect("dashboard")
        else:
            return render(request, "two_factor.html", {"error": "Invalid OTP. Please try again."})

    generate_otp(request.user)  # Ensure OTP is generated for the user
    return render(request, "two_factor.html")  # Ensure return is inside function

@login_required
def logout_view(request):
    """
    Logout function that clears the 2FA session.
    """
    request.session.pop("2fa_verified", None)
    logout(request)
    return redirect("login")


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.password = make_password(form.cleaned_data["password"])
            user.save()

            # ✅ Fix: Pass `request` explicitly to authenticate
            authenticated_user = authenticate(
                request=request, username=user.username, password=form.cleaned_data["password"]
            )

            if authenticated_user:
                reset(request)  # ✅ Reset failed login attempts for this user
                login(request, authenticated_user)
                return redirect("admin_dashboard")

        return render(request, "register.html", {"form": form})

    form = RegisterForm()
    return render(request, "register.html", {"form": form})

@login_required
def dashboard(request):
    if request.user.role == "admin":
        return render(request, "admin_dashboard.html")
    elif request.user.role == "employee":
        return render(request, "employee_dashboard.html")
    else:
        return render(request, "guest_dashboard.html")


def access_denied(request):
    return render(request, "access_denied.html", {"error": "You do not have permission to access this page."})
@login_required
@user_passes_test(lambda u: u.role == 'admin')
def admin_dashboard(request):
    tasks = Task.objects.all()
    notifications = Notification.objects.all()
    return render(request, 'admin_dashboard.html', {
        'tasks': tasks,
        'notifications': notifications
    })

@login_required
@role_required("editor")
def editor_dashboard(request):
    return render(request, "editor_dashboard.html")

@login_required
def employee_dashboard(request):
    user = request.user
    uploaded_files = UploadedFile.objects.filter(user=user)  # If you have this model for file uploads
    tasks = Task.objects.filter(user=user)  # Query tasks for the logged-in user
    notifications = Notification.objects.filter(user=user)  # Query notifications for the logged-in user
    return render(request, 'employee_dashboard.html', {
        'user': user,
        'uploaded_files': uploaded_files,
        'tasks': tasks,
        'notifications': notifications
    })

@login_required
@role_required("viewer")
def viewer_dashboard(request):
    return render(request, "viewer_dashboard.html")


@login_required
def manage_users(request):
    users = CustomUser.objects.all()  # Get all users
    return render(request, "manage_users.html", {"users": users})

@login_required
def view_logs(request):
    logs_path = os.path.join("logs", "security.log")  # ✅ Ensure correct log file path

    logs = []
    if os.path.exists(logs_path):
        with open(logs_path, "r") as file:
            logs = file.readlines()[-50:]  # Get last 50 log entries for performance

    return render(request, "view_logs.html", {"logs": logs})

@login_required
def edit_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        form = EditUserForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect("manage_users")  # ✅ Redirect back to user management

    else:
        form = EditUserForm(instance=user)

    return render(request, "edit_user.html", {"form": form, "user": user})

@login_required
def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    return redirect('manage_users')  # Make sure 'manage_users' exists in `urls.py`

@login_required
def add_user(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])  # Password is hashed
            user.save()
            messages.success(request, "User created successfully!")
            return redirect('user_list')  # Redirect to the user list page
    else:
        form = UserForm()
    return render(request, 'add_user.html', {'form': form})

def user_list(request):
    users = CustomUser.objects.all()
    return render(request, 'user_list.html', {'users': users})

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)  # Keeps the user logged in
            return redirect('employee_dashboard')  # Redirect to the dashboard after successful password change
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password.html', {'form': form})

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            # Save the uploaded file (e.g., in 'uploads/' folder)
            with open(f'uploads/{uploaded_file.name}', 'wb') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)
            return redirect('employee_dashboard')
    else:
        form = FileUploadForm()
    return render(request, 'upload_file.html', {'form': form})

@user_passes_test(lambda u: u.role == 'admin')
def create_task(request):
    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            form.save()  # Save the task to the database
            return redirect('admin_dashboard')  # Redirect to the admin dashboard after saving the task
        else:
            # Optionally, print form errors for debugging
            print(form.errors)
    else:
        form = TaskForm()
    return render(request, 'create_task.html', {'form': form})

# Ensure only admin users can access this view
@user_passes_test(lambda u: u.role == 'admin')
def create_notification(request):
    if request.method == 'POST':
        form = NotificationForm(request.POST)
        if form.is_valid():
            form.save()  # Save the notification to the database
            return redirect('admin_dashboard')  # Redirect to the admin dashboard or notification list
    else:
        form = NotificationForm()
    return render(request, 'create_notification.html', {'form': form})

def bulk_user_upload(csv_file):
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header row
        for row in reader:
            username, email, role, password = row
            user = get_user_model().objects.create_user(
                username=username,
                email=email,
                role=role,
            )
            user.set_password(password)
            user.save()