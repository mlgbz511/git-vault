import os
import sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("ANTIGRAVITY_SIDECAR_WEB_PORT", 8769))

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Git-Vault 控制台</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 100%; height: 100%; overflow: hidden; background: #0d1117; }
    iframe { width: 100%; height: 100%; border: none; display: block; }
  </style>
</head>
<body>
  <iframe src="http://127.0.0.1:8765/" allow="clipboard-read; clipboard-write"></iframe>
</body>
</html>
""".encode("utf-8")

class SidecarHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML_PAGE)))
        self.end_headers()
        self.wfile.write(HTML_PAGE)

    def log_message(self, format, *args):
        pass

def run():
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(("127.0.0.1", PORT), SidecarHandler)
    server.serve_forever()

if __name__ == "__main__":
    run()
