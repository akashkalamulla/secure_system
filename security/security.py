from django.http import HttpResponse

ALLOWED_ADMIN_IPS = ['192.168.1.100', '203.0.113.5']  # Example IPs

def check_admin_ip(request):
    user_ip = request.META.get('REMOTE_ADDR')
    if request.user.is_authenticated and request.user.role == 'admin':
        if user_ip not in ALLOWED_ADMIN_IPS:
            return HttpResponse('Access Denied: Unauthorized IP', status=403)
    return None