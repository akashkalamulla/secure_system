import logging

# Configure security logger
logger = logging.getLogger("security")
logger.setLevel(logging.WARNING)

# Log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Log file
file_handler = logging.FileHandler('logs/security.log')
file_handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(file_handler)

def log_security_event(event_type, message):
    """
    Logs security-related events such as failed logins or suspicious activities.
    """
    logger.warning(f"{event_type}: {message}")
