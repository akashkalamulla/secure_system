import csv
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from .forms import LoginForm
from django.contrib.auth import get_user_model
from .models import CustomUser
from django_ratelimit.decorators import ratelimit
from axes.decorators import axes_dispatch
from . import log_failed_login
from django.contrib.auth.decorators import login_required

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
def dashboard(request):
    if request.user.role == "admin":
        return render(request, "admin_dashboard.html")
    elif request.user.role == "employee":
        return render(request, "employee_dashboard.html")
    else:
        return render(request, "guest_dashboard.html")
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