from django_otp.plugins.otp_email.models import EmailDevice
from django.core.mail import send_mail
import random

def generate_otp(user):
    """
    Generates a 6-digit OTP and sends it via email.
    """
    otp = random.randint(100000, 999999)
    email_device, created = EmailDevice.objects.get_or_create(user=user, name="default")
    email_device.token = str(otp)
    email_device.save()

    send_mail(
        "Your 2FA Code",
        f"Your One-Time Password (OTP) is {otp}. Do not share this code with anyone.",
        "noreply@yourdomain.com",
        [user.email],
        fail_silently=False,
    )
    return otp

def verify_otp(user, otp):
    """
    Verifies the OTP entered by the user.
    """
    try:
        email_device = EmailDevice.objects.get(user=user, name="default")
        return email_device.verify_token(otp)
    except EmailDevice.DoesNotExist:
        return False
