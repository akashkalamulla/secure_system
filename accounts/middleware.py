from django.utils.deprecation import MiddlewareMixin
from django.utils.timezone import now
from django.conf import settings

class SessionTimeoutMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity', now().timestamp())
            timeout = settings.SESSION_EXPIRE_SECONDS  # Set timeout duration (e.g., 600 seconds = 10 minutes)
            if (now().timestamp() - last_activity) > timeout:
                request.session.flush()  # Log out user after timeout
            else:
                request.session['last_activity'] = now().timestamp()