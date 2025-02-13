import os
import csv
from django.http import HttpResponse
from django.conf import settings
import logging

logger = logging.getLogger("security")

def export_security_logs():
    logs_path = os.path.join(settings.BASE_DIR, 'logs/security.log')

    if not os.path.exists(logs_path):  # Handle missing log file
        return HttpResponse("No security logs found.", content_type="text/plain")

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="security_logs.csv"'
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'IP Address', 'Event'])

    with open(logs_path, 'r') as log_file:
        for line in log_file:
            writer.writerow(line.strip().split(','))

    return response

def log_failed_login(username, ip_address):
    logger.warning(f"Failed login attempt for {username} from {ip_address}")
