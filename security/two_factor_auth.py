from django_otp.plugins.otp_email.models import EmailDevice
from django.core.mail import send_mail
import random
import time

OTP_VALIDITY_PERIOD = 300  # 5 minutes
OTP_ATTEMPT_LIMIT = 3
otp_attempts = {}

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

    otp_attempts[user.username] = {"timestamp": time.time(), "attempts": 0}
    return otp

def verify_otp(user, otp):
    """
    Verifies the OTP entered by the user.
    """
    current_time = time.time()

    if user.username not in otp_attempts:
        return False

    elapsed_time = current_time - otp_attempts[user.username]["timestamp"]

    if elapsed_time > OTP_VALIDITY_PERIOD:
        return False  # OTP expired

    if otp_attempts[user.username]["attempts"] >= OTP_ATTEMPT_LIMIT:
        return False  # Too many attempts

    try:
        email_device = EmailDevice.objects.get(user=user, name="default")
        if email_device.verify_token(otp):
            otp_attempts.pop(user.username, None)  # Clear attempt record
            return True
        else:
            otp_attempts[user.username]["attempts"] += 1
            return False
    except EmailDevice.DoesNotExist:
        return False
