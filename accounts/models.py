from django.contrib.auth.models import AbstractUser, User
from django.db import models

from secure_system import settings


class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('employee', 'Employee'),
        ('guest', 'Guest'),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='employee')
    admin_id = models.CharField(max_length=10, unique=True, blank=True, null=True)
    employee_id = models.CharField(max_length=10, unique=True, blank=True, null=True)

    def has_permission(self, permission):
        """
        Checks if the user has the required permission.
        """
        role_permissions = {
            "admin": ["add", "edit", "delete", "view"],
            "editor": ["edit", "view"],
            "viewer": ["view"],
        }
        return permission in role_permissions.get(self.role, [])

    def generate_unique_id(self, prefix):
        """
        Generates a unique ID for users based on their role.
        Ensures there are no duplicates.
        """
        last_user = CustomUser.objects.filter(employee_id__startswith=prefix).order_by('-id').first()
        new_id = f"{prefix}001" if not last_user else f"{prefix}{str(int(last_user.employee_id[1:]) + 1).zfill(3)}"

        # Ensure uniqueness by checking the database
        while CustomUser.objects.filter(employee_id=new_id).exists():
            new_id = f"{prefix}{str(int(new_id[1:]) + 1).zfill(3)}"

        return new_id

    def save(self, *args, **kwargs):
        """
        Ensures `admin_id` and `employee_id` are generated uniquely.
        """
        if self.role == "admin" and not self.admin_id:
            last_admin = CustomUser.objects.filter(role="admin").order_by('-id').first()
            self.admin_id = f"A{str(last_admin.id + 1).zfill(3)}" if last_admin else "A001"

        if self.role == "employee" and not self.employee_id:
            self.employee_id = self.generate_unique_id("E")

        if self.role == "guest" and not self.employee_id:
            self.employee_id = self.generate_unique_id("G")

        super().save(*args, **kwargs)

class UploadedFile(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

# Task Model
class Task(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField(default="No description")  # Task description field
    due_date = models.DateTimeField()
    status = models.CharField(max_length=50, choices=[('Assign', 'Assign'),('Pending', 'Pending'), ('Completed', 'Completed')])

    def __str__(self):
        return self.name

# Notification Model
class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.username} at {self.date}"