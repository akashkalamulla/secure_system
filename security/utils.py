from django.core.mail import send_mail
from django.conf import settings

def send_security_alert(email, message):
    send_mail(
        'Security Alert',
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )