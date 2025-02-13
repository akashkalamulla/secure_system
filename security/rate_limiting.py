from django_ratelimit.decorators import ratelimit

def apply_rate_limit(rate="5/m"):
    """
    Decorator to apply rate limiting to multiple views.
    Usage: @apply_rate_limit("10/m")
    """
    return ratelimit(key="ip", rate=rate, method="POST", block=True)
