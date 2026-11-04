"""Real Chromium regression, run explicitly after the OIDC browser installation."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright


SPEC = importlib.util.spec_from_file_location(
    "official_plan", Path(__file__).resolve().parents[1] / "run-official-plan.py",
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
LOGIN_PATH = "/_coauth/account/auth/login"


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, content_type, body, *, cookie=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", "fixture=accepted; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/complete":
            self.reply(200, "text/html", b"<p>Navigation completed</p>")
            return
        case = parse_qs(urlsplit(self.path).query).get("case", ["success"])[0]
        assert case in {"success", "denied", "malformed"}
        target = json.dumps(LOGIN_PATH + "?case=" + case)
        html = """<button>Sign in</button><script>
document.querySelector('button').onclick = async () => {
 const response = await fetch(TARGET, {method: 'POST'});
 await response.text(); location.href = '/complete';
};</script>""".replace("TARGET", target)
        self.reply(200, "text/html", html.encode())

    def do_POST(self):
        parsed = urlsplit(self.path)
        assert parsed.path == LOGIN_PATH
        case = parse_qs(parsed.query)["case"][0]
        status, body = {
            "success": (200, b'{"status":"success"}'),
            "denied": (401, b'{"status":"error","error":"invalid_credentials"}'),
            "malformed": (200, b"not-json"),
        }[case]
        self.server.posts += 1
        self.reply(status, "application/json", body, cookie=case == "success")


class BrowserResponseNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.server.posts = 0
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls.playwright.stop()
        finally:
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join()

    def observe(self, case, check):
        page = self.browser.new_page()
        session = RUNNER.retain_browser_responses(page)
        before = self.server.posts
        try:
            page.goto(self.base + "/?case=" + case)
            with page.expect_response(lambda reply: urlsplit(reply.url).path == LOGIN_PATH
                                      and reply.request.method == "POST") as login:
                page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url(self.base + "/complete")
            self.assertEqual(self.server.posts, before + 1)
            check(login.value)
            cookies = page.context.cookies()
            if case == "success":
                self.assertTrue(any(c["name"] == "fixture" and c["value"] == "accepted"
                                    and c["httpOnly"] for c in cookies))
            else:
                self.assertEqual(cookies, [])
        finally:
            try:
                session.detach()
            finally:
                page.close()

    def test_success_body_survives_real_document_navigation(self):
        def check(response):
            self.assertEqual(response.status, 200)
            self.assertEqual(response.json(), {"status": "success"})

        self.observe("success", check)

    def test_http_failure_is_preserved_after_navigation(self):
        def check(response):
            self.assertEqual(response.status, 401)
            self.assertEqual(response.json(), {"status": "error", "error": "invalid_credentials"})

        self.observe("denied", check)

    def test_malformed_json_still_fails_after_navigation(self):
        def check(response):
            self.assertEqual(response.status, 200)
            with self.assertRaises(json.JSONDecodeError):
                response.json()

        self.observe("malformed", check)


if __name__ == "__main__":
    unittest.main()
