#!/usr/bin/env python3
"""
Simple HTTP Server for CVE Visualizer

Run this script to serve the visualizer locally:
    python3 serve.py

Then open: http://localhost:5000/visualizer/cve-visualizer.html
"""

import http.server
import socketserver
import os
import sys
from pathlib import Path

PORT = 5000

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add headers to prevent caching and allow CORS
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        # Log requests
        print(f"GET {self.path}")
        super().do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

def main():
    # Change to project root (parent of src/)
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)

    print(f"\n{'='*60}")
    print("CVE Visualizer Server")
    print(f"{'='*60}")
    print(f"\nServing from: {project_root}")
    print(f"http://localhost:{PORT}/visualizer/cve-visualizer.html")
    print(f"\nPress Ctrl+C to stop\n")

    try:
        with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
            print(f"Server running on http://localhost:{PORT}/visualizer/cve-visualizer.html")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nServer stopped.")
        sys.exit(0)
    except OSError as e:
        print(f"\nError: {e}")
        if "Address already in use" in str(e):
            print(f"Port {PORT} is already in use. Try using a different port.")
        sys.exit(1)

if __name__ == '__main__':
    main()
