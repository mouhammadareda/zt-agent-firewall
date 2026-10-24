"""Mock attacker endpoint (lab only). Records every request it receives so the evaluation can
count successful exfiltration from evidence, not from what the model says."""
import json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = os.getenv("HITS_FILE", "/data/hits.jsonl")


class H(BaseHTTPRequestHandler):
    def _rec(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "method": self.command, "path": self.path, "body": body[:5000]}) + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    do_GET = do_POST = _rec

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    HTTPServer(("0.0.0.0", 9000), H).serve_forever()
