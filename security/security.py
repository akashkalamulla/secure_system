from django.conf import settings

# Security configurations
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = not settings.DEBUG
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = 'DENY'


# Apply security settings to Django settings
def apply_security_settings():
    settings.SECURE_BROWSER_XSS_FILTER = SECURE_BROWSER_XSS_FILTER
    settings.SECURE_CONTENT_TYPE_NOSNIFF = SECURE_CONTENT_TYPE_NOSNIFF
    settings.SECURE_SSL_REDIRECT = SECURE_SSL_REDIRECT
    settings.SESSION_COOKIE_SECURE = SESSION_COOKIE_SECURE
    settings.CSRF_COOKIE_SECURE = CSRF_COOKIE_SECURE
    settings.X_FRAME_OPTIONS = X_FRAME_OPTIONS
