#!/usr/bin/env python3
"""
DC Exporter Metrics Server
Serves metrics.txt file via HTTP on port 9835
"""
import http.server
import socketserver
import os

class ReuseAddrTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class MetricsHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics" or self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            try:
                with open("metrics.txt", "r") as f:
                    self.wfile.write(f.read().encode())
            except FileNotFoundError:
                self.wfile.write(b"# No metrics yet\n")
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress logging

if __name__ == "__main__":
    PORT = 9835
    os.chdir("/opt/dc-exporter")
    
    with ReuseAddrTCPServer(("", PORT), MetricsHandler) as httpd:
        print(f"DC Exporter serving on port {PORT}")
        httpd.serve_forever()
