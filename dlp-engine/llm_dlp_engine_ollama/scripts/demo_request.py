import json, requests

event = {
  "channel": "web_upload",
  "destination": "https://example-upload.local/upload",
  "content_type": "txt",
  "extracted_text": "Employee Record\nName: Alex Jordan\nSSN: 123-45-6789\nNotes: confidential - do not distribute\n",
  "metadata": {"filename": "employees.txt", "size": "1KB"},
  "encryption_visibility": "decrypted"
}

r = requests.post("http://localhost:8000/analyze?use_llm=1&model=llama3.1:8b", json=event, timeout=120)
print("Status:", r.status_code)
print(json.dumps(r.json(), indent=2))
