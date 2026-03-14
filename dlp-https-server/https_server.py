from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        html = b"""<html><body>
        <h2>Exfil Test Portal (HTTPS)</h2>
        <form method="POST" action="/submit">
          <textarea name="data" rows="12" cols="80">Paste text here...</textarea><br/>
          <button type="submit">Submit</button>
        </form>
        </body></html>"""
        self.send_response(200)
        self.send_header("Content-Type","text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        length = int(self.headers.get("Content-Length","0"))
        body = self.rfile.read(length)
        print("\n=== HTTPS SERVER RECEIVED POST ===")
        print("Path:", self.path)
        print("Body (first 300 bytes):", body[:300])
        resp = b"received"
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

httpd = HTTPServer(("0.0.0.0", 9443), Handler)
httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="key.pem", certfile="cert.pem", server_side=True)
httpd.serve_forever()
