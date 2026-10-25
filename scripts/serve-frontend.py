#!/usr/bin/env python3
"""Serve the frontend locally, proxy backend APIs, and optionally rebuild on edits."""
import argparse
import http.client
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "crates" / "frontend"
API_PATHS = ("/_coauth/", "/api/", "/upstream/", "/.well-known/", "/oauth2/")
API_ROUTES = {"/authorize", "/health", "/connection-info", "/oauth/token", "/oauth/revoke"}
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8182)
    parser.add_argument("--backend", default="http://127.0.0.1:7080")
    parser.add_argument("--watch", action="store_true")
    args = parser.parse_args()
    backend = urlsplit(args.backend)
    if backend.scheme not in {"http", "https"} or not backend.hostname:
        parser.error("--backend must be an HTTP(S) origin")
    output = ROOT / "dist"
    build = [sys.executable, str(ROOT / "scripts" / "build-frontend.py"), "--out-dir", str(output)]
    subprocess.run(build, cwd=ROOT, check=True)
    revision = [1]
    stopped = threading.Event()

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *values, **options):
            super().__init__(*values, directory=str(output), **options)

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def proxy(self):
            connection_type = http.client.HTTPSConnection if backend.scheme == "https" else http.client.HTTPConnection
            connection = connection_type(backend.hostname, backend.port, timeout=65)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else None
                headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS | {"host", "content-length"}}
                headers["Host"] = backend.netloc
                connection.request(self.command, backend.path.rstrip("/") + self.path, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in HOP_HEADERS | {"content-length", "cache-control"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except (OSError, http.client.HTTPException, ValueError) as error:
                self.send_error(502, f"Backend proxy failed: {error}")
            finally:
                connection.close()

        def do_GET(self):
            path = urlsplit(self.path).path
            if path.startswith(API_PATHS) or path in API_ROUTES:
                self.proxy()
            elif path == "/__coauth_reload":
                payload = json.dumps({"revision": revision[0]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            elif not Path(path).suffix or path == "/index.html":
                html = (output / "index.html").read_text(encoding="utf-8")
                if args.watch:
                    html = html.replace("</body>", "<script>let revision;setInterval(async()=>{try{const r=await fetch('/__coauth_reload').then(r=>r.json());if(revision!==undefined&&revision!==r.revision)location.reload();revision=r.revision}catch{}},800)</script></body>")
                payload = html.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                super().do_GET()

        def do_HEAD(self):
            path = urlsplit(self.path).path
            if path.startswith(API_PATHS) or path in API_ROUTES:
                self.proxy()
            else:
                super().do_HEAD()

        do_POST = proxy
        do_PUT = proxy
        do_PATCH = proxy
        do_DELETE = proxy
        do_OPTIONS = proxy

    def snapshot():
        folders = [FRONTEND / "src", FRONTEND / "assets", FRONTEND / "web", ROOT / "translations"]
        files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", FRONTEND / "Cargo.toml"]
        for folder in folders:
            files.extend(path for path in folder.rglob("*") if path.is_file())
        return tuple(sorted((str(path), path.stat().st_mtime_ns) for path in files if path.exists()))

    def watch():
        current = snapshot()
        while not stopped.wait(0.5):
            changed = snapshot()
            if changed == current:
                continue
            current = changed
            result = subprocess.run(build, cwd=ROOT, check=False)
            if result.returncode == 0:
                revision[0] += 1
            else:
                print("Frontend rebuild failed; waiting for the next edit", file=sys.stderr)

    mimetypes.add_type("application/wasm", ".wasm")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if args.watch:
        threading.Thread(target=watch, daemon=True).start()
    print(f"Frontend: http://127.0.0.1:{args.port}; backend: {args.backend}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set()
        server.server_close()


if __name__ == "__main__":
    main()
