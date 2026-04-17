from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        html = """
<!DOCTYPE html>
<html>
<head>
<title>DLP Inspection Portal</title>
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
    border-bottom: 1px solid #7f1d1d;
    display: flex;
    justify-content: space-between;
}
.badge {
    background: #7f1d1d;
    color: #ef4444;
    padding: 6px 12px;
    border-radius: 8px;
}
.warning {
    background: #7f1d1d;
    color: #fecaca;
    padding: 10px;
    text-align: center;
}
.container {
    max-width: 900px;
    margin: 40px auto;
    background: #020617;
    padding: 30px;
    border-radius: 16px;
    border: 1px solid #7f1d1d;
}
textarea {
    width: 100%;
    height: 180px;
    background: #0f172a;
    border: 1px solid #7f1d1d;
    border-radius: 10px;
    padding: 12px;
    color: white;
}
button {
    margin-top: 20px;
    padding: 10px 18px;
    border-radius: 8px;
    border: none;
    background: #ef4444;
    color: white;
    cursor: pointer;
}
.footer {
    margin-top: 20px;
    font-size: 12px;
    color: #fca5a5;
}
</style>
</head>
<body>

<div class="header">
    <h1>DLP Inspection Portal</h1>
    <div class="badge">⚠ HTTP UNENCRYPTED</div>
</div>

<div class="warning">
    Warning: This channel is not encrypted.
</div>

<div class="container">
    <h2>Submit Data for Inspection</h2>

    <form method="POST" action="/submit">
        <textarea name="data" placeholder="Paste sensitive content here..."></textarea>
        <br>
        <button type="submit">Inspect & Send</button>
    </form>

    <div class="footer">Unsecured Channel • Monitored</div>
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

        print("\n=== HTTP RAW REQUEST ===")
        print(raw_body[:300])

        parsed = urllib.parse.parse_qs(raw_body.decode("utf-8"))
        text_data = parsed.get("data", [""])[0]

        if text_data:
            print("Text:", text_data[:200])

        resp = "Submission processed (insecure channel).".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
