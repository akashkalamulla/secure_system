from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('employee', 'Employee'),
        ('guest', 'Guest'),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='employee')
    admin_id = models.CharField(max_length=10, unique=True, blank=True, null=True)
    employee_id = models.CharField(max_length=10, unique=True, blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.role == "admin" and not self.admin_id:
            last_admin = CustomUser.objects.filter(role="admin").order_by('-id').first()
            self.admin_id = f"A{str(last_admin.id + 1).zfill(3)}" if last_admin else "A001"

        if self.role == "employee" and not self.employee_id:
            last_employee = CustomUser.objects.filter(role="employee").order_by('-id').first()
            self.employee_id = f"E{str(last_employee.id + 1).zfill(3)}" if last_employee else "E001"

        if self.role == "guest" and not self.employee_id:
            last_guest = CustomUser.objects.filter(role="guest").order_by('-id').first()
            self.employee_id = f"G{str(last_guest.id + 1).zfill(3)}" if last_guest else "G001"

        super().save(*args, **kwargs)
