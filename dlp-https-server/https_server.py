from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import io
import urllib.parse

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        html = """
<!DOCTYPE html>
<html>
<head>
<title>DLP Secure Portal</title>
<style>
body {
    margin: 0;
    font-family: "Segoe UI", Arial;
    background: #0f172a;
    color: #e2e8f0;
}
.header {
    background: #020617;
    padding: 16px 24px;
    border-bottom: 1px solid #1e293b;
    display: flex;
    justify-content: space-between;
}
.badge {
    background: #14532d;
    color: #22c55e;
    padding: 6px 12px;
    border-radius: 8px;
}
.container {
    max-width: 900px;
    margin: 40px auto;
    background: #020617;
    padding: 30px;
    border-radius: 16px;
    border: 1px solid #1e293b;
}
textarea {
    width: 100%;
    height: 180px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 12px;
    color: white;
}
button {
    margin-top: 20px;
    padding: 10px 18px;
    border-radius: 8px;
    border: none;
    background: #22c55e;
    color: white;
    cursor: pointer;
}
.footer {
    margin-top: 20px;
    font-size: 12px;
    color: #64748b;
}
</style>
</head>
<body>

<div class="header">
    <h1>DLP Secure Inspection Portal</h1>
    <div class="badge">🔒 HTTPS SECURE</div>
</div>

<div class="container">
    <h2>Submit Data for Inspection</h2>
    <p style="color:#94a3b8;">All data is encrypted and inspected by DLP.</p>

    <form method="POST" action="/submit">
        <textarea name="data" placeholder="Paste sensitive content here..."></textarea>
        <br>
        <button type="submit">Inspect & Send</button>
    </form>

    <div class="footer">Secure Inline DLP Channel</div>
</div>

</body>
</html>
"""
        encoded = html.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        print("\n=== HTTPS RAW REQUEST ===")
        print(raw_body[:300])

        parsed = urllib.parse.parse_qs(raw_body.decode("utf-8"))
        text_data = parsed.get("data", [""])[0]

        if text_data:
            print("Text:", text_data[:200])

        resp = "Secure submission processed successfully.".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


httpd = HTTPServer(("0.0.0.0", 9443), Handler)
httpd.socket = ssl.wrap_socket(
    httpd.socket,
    keyfile="key.pem",
    certfile="cert.pem",
    server_side=True
)

httpd.serve_forever()
