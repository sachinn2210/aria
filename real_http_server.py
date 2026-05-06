"""
Simple HTTP Server with Real Access Logging
Run this to generate real HTTP access logs
"""

import http.server
import socketserver
import logging
from datetime import datetime

PORT = 8080  # Change this to 8081 or 9000 if port is already in use
LOG_FILE = "logs/real_http.log"

# Create logs directory
import os
os.makedirs("logs", exist_ok=True)

# Setup logging in Apache combined format
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(message)s'
)

class LoggingHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        """Override to write Apache-style logs"""
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        log_line = f'{self.client_address[0]} - - [{timestamp}] "{format % args}"'
        logging.info(log_line)
        print(log_line)  # Also print to console

with socketserver.TCPServer(("", PORT), LoggingHTTPRequestHandler) as httpd:
    print(f"[Real HTTP Server] Running on http://localhost:{PORT}")
    print(f"[Real HTTP Server] Logs writing to: {LOG_FILE}")
    print(f"[Real HTTP Server] Open browser and visit URLs to generate real logs!")
    print(f"\nTry these URLs:")
    print(f"  http://localhost:{PORT}/")
    print(f"  http://localhost:{PORT}/admin")
    print(f"  http://localhost:{PORT}/../../../etc/passwd")
    print(f"  http://localhost:{PORT}/.env")
    print(f"  http://localhost:{PORT}/wp-admin")
    httpd.serve_forever()
