import csv
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from .forms import LoginForm
from django.contrib.auth import get_user_model
from .models import CustomUser
from django_ratelimit.decorators import ratelimit
from axes.decorators import axes_dispatch
from security.logs import log_failed_login
from django.contrib.auth.decorators import login_required
from security.two_factor_auth import generate_otp, verify_otp
from django.contrib.auth import logout


def home(request):
    return render(request, "home.html")
@axes_dispatch
@ratelimit(key="ip", rate="5/m", method="POST", block=True)
def login_view(request):
    if request.method == "POST":
        admin_id = request.POST.get("admin_id")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(admin_id=admin_id)
            authenticated_user = authenticate(username=user.username, password=password)

            if authenticated_user:
                login(request, authenticated_user)
                return redirect("admin_dashboard")
            if not authenticated_user:
                log_failed_login(admin_id)
                return render(request, "login.html", {"error": "Invalid credentials"})
            else:
                return render(request, "login.html", {"error": "Invalid credentials"})

        except CustomUser.DoesNotExist:
            return render(request, "login.html", {"error": "Invalid Admin ID"})

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
            return render(request, "two_factor.html", {"error": "Invalid OTP"})

    generate_otp(request.user)
    return render(request, "two_factor.html")

@login_required
def logout_view(request):
    """
    Logout function that clears the 2FA session.
    """
    request.session.pop("2fa_verified", None)
    logout(request)
    return redirect("login")

@login_required
def dashboard(request):
    if request.user.role == "admin":
        return render(request, "admin_dashboard.html")
    elif request.user.role == "employee":
        return render(request, "employee_dashboard.html")
    else:
        return render(request, "guest_dashboard.html")

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

@login_required
@role_required("admin")
def admin_dashboard(request):
    return render(request, "admin_dashboard.html")

@login_required
@role_required("editor")
def editor_dashboard(request):
    return render(request, "editor_dashboard.html")

@login_required
@role_required("viewer")
def viewer_dashboard(request):
    return render(request, "viewer_dashboard.html")

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