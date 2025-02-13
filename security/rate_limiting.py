from django_ratelimit.decorators import ratelimit

def apply_rate_limit(view_func):
    """
    Decorator to apply rate limiting to a view.
    """
    return ratelimit(key="ip", rate="5/m", method="POST", block=True)(view_func)
