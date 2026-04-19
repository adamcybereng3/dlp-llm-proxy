from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import urllib.parse

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        html = """
<!DOCTYPE html>
<html>
<head>
<title>DLP Processing Portal</title>
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
    border-bottom: 1px solid #14532d;
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
    border: 1px solid #14532d;
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
button:hover {
    background: #16a34a;
}
.footer {
    margin-top: 20px;
    font-size: 12px;
    color: #94a3b8;
}
</style>
</head>
<body>

<div class="header">
    <h1>DLP Processing Portal</h1>
    <div class="badge">HTTPS Processing</div>
</div>

<div class="container">
    <h2>Submit Data for Inspection</h2>

    <form method="POST" action="/submit">
        <textarea name="data" placeholder="Paste content here for processing..."></textarea>
        <br>
        <button type="submit">Process Request</button>
    </form>

    <div class="footer">Inline Data Protection Inspection</div>
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

        # 🔥 Fancy response page
        html = """
<!DOCTYPE html>
<html>
<head>
<title>Submission Processed</title>
<style>
body {
    font-family: Arial, sans-serif;
    background: linear-gradient(135deg, #0f172a, #022c22);
    color: #ecfdf5;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}
.card {
    background: #022c22;
    padding: 40px;
    border-radius: 16px;
    box-shadow: 0 0 30px rgba(0,255,150,0.2);
    text-align: center;
    border: 1px solid #14532d;
}
h1 {
    color: #22c55e;
    margin-bottom: 10px;
}
p {
    color: #d1fae5;
}
.badge {
    margin-top: 15px;
    display: inline-block;
    padding: 6px 14px;
    background: #14532d;
    border-radius: 8px;
    font-size: 14px;
    color: #22c55e;
}
</style>
</head>
<body>

<div class="card">
    <h1>Submission Processed</h1>
    <p>Your request has been successfully processed by the DLP system.</p>
    <div class="badge">HTTPS Processing</div>
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


httpd = HTTPServer(("0.0.0.0", 9443), Handler)

httpd.socket = ssl.wrap_socket(
    httpd.socket,
    keyfile="key.pem",
    certfile="cert.pem",
    server_side=True
)

httpd.serve_forever()
