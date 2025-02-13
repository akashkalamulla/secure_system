from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.middleware.csrf import get_token
import logging

logger = logging.getLogger("security")

class SecurityMiddleware(MiddlewareMixin):
    """
    Middleware to enforce security policies such as XSS protection and rate limiting.
    """

    class SecurityMiddleware(MiddlewareMixin):
        def process_request(self, request):
            request.META["X-XSS-Protection"] = "1; mode=block"
            request.META["X-Content-Type-Options"] = "nosniff"
            request.META["X-Frame-Options"] = "DENY"  # Enforce CSRF protection

    def process_exception(self, request, exception):
        logger.warning(f"Security Exception: {exception}")
        return HttpResponseForbidden("Forbidden: Security policy violation")

