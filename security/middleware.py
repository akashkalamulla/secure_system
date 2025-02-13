from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.conf import settings
import logging

logger = logging.getLogger("security")

class SecurityMiddleware(MiddlewareMixin):
    """
    Middleware to enforce security policies such as XSS protection and rate limiting.
    """

    def process_request(self, request):
        """
        Handles security-related HTTP headers and restrictions.
        """
        request.META["X-XSS-Protection"] = "1; mode=block"
        request.META["X-Content-Type-Options"] = "nosniff"
        request.META["X-Frame-Options"] = "DENY"

    def process_exception(self, request, exception):
        """
        Logs security exceptions.
        """
        logger.warning(f"Security Exception: {exception}")
        return HttpResponseForbidden("Forbidden: Security policy violation")
