import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import expect, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
BASE = "/labs/google-signin"
IDP = BASE + "/idp"
HOST = "ctf.hackmestepbro.com"
DOMAIN = "hackmestepbro.com"


class BrowserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="browser-", dir=ROOT / "data")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.netlog = cls.directory / "netlog.json"
        cls._native_test_ran = False
        cert, key = (cls.directory / name for name in ("cert.pem", "key.pem"))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST},DNS:{DOMAIN}",
             "-keyout", str(key), "-out", str(cert)],
            check=True, capture_output=True,
        )
        pubkey = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"])
        pubkey_der = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pubkey)
        cls.spki = base64.b64encode(hashlib.sha256(pubkey_der).digest()).decode()

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            app_port = sock.getsockname()[1]
        cls.requests = []
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), cls.proxy_handler(app_port))
        cls.addClassCleanup(proxy.server_close)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        cls.addClassCleanup(proxy.shutdown)
        cls.port = proxy.server_port
        cls.origin = f"https://{HOST}:{cls.port}"

        log = (cls.directory / "puma.log").open("w+")
        cls.addClassCleanup(log.close)
        puma = subprocess.Popen(
            ["./start.sh"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "PORT": str(app_port), "PUBLIC_ORIGIN": cls.origin,
                 "LAB_DATA_DIR": str(cls.directory / "app")},
        )
        cls.addClassCleanup(cls.stop_puma, puma)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", app_port), timeout=0.1):
                    break
            except OSError:
                if puma.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read()) from None
                time.sleep(0.05)
        else:
            raise RuntimeError("Puma startup timed out.")

        old_tmp = os.environ.get("TMPDIR")
        os.environ["TMPDIR"] = str(cls.directory)
        cls.addClassCleanup(cls.restore_tmp, old_tmp)
        playwright = sync_playwright().start()
        cls.addClassCleanup(playwright.stop)
        cls.browser = playwright.chromium.launch(
            headless=True, executable_path=os.environ.get("LUMORA_CHROMIUM"),
            env={**os.environ, "XDG_CACHE_HOME": str(cls.directory / "cache"),
                 "XDG_CONFIG_HOME": str(cls.directory / "config")},
            args=[
                "--no-proxy-server",
                f"--host-resolver-rules=MAP {HOST} 127.0.0.1, MAP {DOMAIN}:443 127.0.0.1:{cls.port}",
                f"--ignore-certificate-errors-spki-list={cls.spki}",
                f"--log-net-log={cls.netlog}",
            ],
        )
        cls.addClassCleanup(cls.close_browser_and_check_netlog)
        print(f"Chromium {cls.browser.version} over local HTTPS", flush=True)

    @staticmethod
    def restore_tmp(original):
        if original is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = original

    @classmethod
    def close_browser_and_check_netlog(cls):
        cls.browser.close()
        netlog = json.loads(cls.netlog.read_text())
        root_path = "/.well-known/web-identity"
        urls = {event.get("params", {}).get("url") for event in netlog["events"]}
        root_fetches = {url for url in urls if url and url.endswith(root_path) and IDP not in url}
        if cls._native_test_ran:
            expected = {f"https://{DOMAIN}{root_path}"}
            if root_fetches != expected:
                raise AssertionError(f"Expected the registrable-domain well-known request, got {root_fetches}.")
            print(f"Chromium requested https://{DOMAIN}{root_path}, got HTTP 404 and completed FedCM", flush=True)

    @staticmethod
    def stop_puma(puma):
        if puma.poll() is None:
            puma.terminate()
            try:
                puma.wait(timeout=5)
            except subprocess.TimeoutExpired:
                puma.kill()
                puma.wait()

    @classmethod
    def proxy_handler(cls, app_port):
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def forward(self):
                if self.path.startswith("/.well-known/"):
                    self.send_error(404)
                    cls.requests.append((self.command, self.path, self.headers.get("Sec-Fetch-Dest"), 404))
                    return
                if self.headers["Host"] != f"{HOST}:{cls.port}" or not self.path.startswith(BASE + "/"):
                    self.send_error(404)
                    return

                connection = http.client.HTTPConnection("127.0.0.1", app_port, timeout=5)
                try:
                    headers = dict(self.headers)
                    headers["X-Forwarded-Proto"] = "https"
                    body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                    connection.request(self.command, self.path, body or None, headers)
                    response = connection.getresponse()
                    content = response.read()
                    cls.requests.append((self.command, self.path, self.headers.get("Sec-Fetch-Dest"), response.status))
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in {"connection", "transfer-encoding", "content-length"}:
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                finally:
                    connection.close()

            do_GET = do_POST = forward

        return Proxy

    def setUp(self):
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.page.set_default_timeout(8000)

    def observe_graphql(self, operation):
        return self.page.expect_request(
            lambda req: req.url == self.origin + BASE + "/graphql"
            and req.method == "POST" and req.post_data_json.get("operationName") == operation
        )

    def assert_persisted_request(self, request):
        body = request.post_data_json
        self.assertNotIn("query", body)
        self.assertRegex(body["extensions"]["operationId"], r"^Lumora/[a-f0-9]{64}$")
        self.assertTrue(request.header_value("x-csrf-token"))

    def assert_oauth_request(self, request, select_by):
        self.assert_persisted_request(request)
        body = request.post_data_json
        values = body["variables"]["input"]
        self.assertTrue(values["idToken"])
        self.assertEqual("GOOGLE_OAUTH2", values["provider"])
        self.assertEqual("WEB", values["platform"])
        self.assertEqual(select_by, self.page.evaluate("sessionStorage.getItem('selectBy')"))

    def observe_credential_callback(self):
        self.page.evaluate("""() => {
          const original = window.handleOneTapCredential;
          window.handleOneTapCredential = details => {
            sessionStorage.setItem("selectBy", details.select_by);
            return original(details);
          };
        }""")

    def assert_dashboard(self, name, *, path=None):
        self.page.wait_for_url(self.origin + BASE + "/")
        expect(self.page.get_by_role("heading", name=f"Welcome back, {name}.")).to_be_visible()
        user = self.page.evaluate("async url => (await (await fetch(url)).json()).user", BASE + "/me")
        self.assertEqual(f"{name.lower()}@lab.test", user["email"])
        expect(self.page.locator("#g_id_onload")).to_have_count(0)
        if path:
            self.assertTrue(any(method == "POST" and request_path == path and code == 200
                                for method, request_path, _, code in self.requests))

    def test_native_fedcm_and_same_site_well_known(self):
        start = len(self.requests)
        self.page.goto(self.origin + IDP + "/signin")
        with self.page.expect_response(lambda res: res.url == self.origin + IDP + "/signin"
                                       and res.request.method == "POST") as signed_in:
            self.page.get_by_role("button", name=re.compile("Alice")).click()
        self.assertEqual("logged-in", signed_in.value.header_value("set-login"))
        expect(self.page.get_by_role("button", name="Agree")).to_be_visible()
        expect(self.page.locator("#g_id_onload")).to_have_count(0)
        self.assertFalse(any(path == IDP + "/gsi/client" for _, path, _, _ in self.requests[start:]))
        self.assertEqual("function", self.page.evaluate("typeof IdentityCredential"))

        cdp = self.context.new_cdp_session(self.page)
        dialogs = []
        console_errors = []
        cdp.on("FedCm.dialogShown", lambda dialog: dialogs.append(dialog))
        self.page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        cdp.send("FedCm.enable", {"disableRejectionDelay": True})
        self.observe_credential_callback()

        with self.observe_graphql("SignInWithOAuthMutation") as oauth_request, self.observe_graphql("DashboardQuery") as dashboard_request:
            self.page.get_by_role("button", name="Agree").click()
            for _ in range(120):
                if dialogs:
                    break
                self.page.wait_for_timeout(50)
            self.assertTrue(dialogs, f"No native dialog. Requests: {self.requests[start:]}. Console: {console_errors}")
            dialog = dialogs[0]
            self.assertIn("Alice", [account["name"] for account in dialog["accounts"]],
                          f"Dialog: {dialog['dialogType']}. Requests: {self.requests[start:]}. Console: {console_errors}")
            index = next(i for i, account in enumerate(dialog["accounts"]) if account["name"] == "Alice")
            cdp.send("FedCm.selectAccount", {"dialogId": dialog["dialogId"], "accountIndex": index})

        self.assert_dashboard("Alice", path=IDP + "/gsi/fedcm/issue")
        self.assert_oauth_request(oauth_request.value, "fedcm")
        self.assert_persisted_request(dashboard_request.value)
        requests = self.requests[start:]
        self.assertIn(("GET", IDP + "/gsi/fedcm.json", "webidentity", 200), requests)
        self.assertIn(("GET", IDP + "/gsi/fedcm/listaccounts", "webidentity", 200), requests)
        self.assertIn(("POST", IDP + "/gsi/fedcm/issue", "webidentity", 200), requests)
        self.assertFalse(any("/fallback/" in path for _, path, _, _ in requests))
        self.assertIn(("GET", "/.well-known/web-identity", "webidentity", 404), requests)
        self.assertFalse(any(path == IDP + "/.well-known/web-identity" for _, path, _, _ in requests))
        type(self)._native_test_ran = True
        print(f"FedCM {dialog['dialogType']} → selectAccount → persisted GraphQL → Alice dashboard", flush=True)

    def test_fallback_dismissal_signin_and_inline_error(self):
        self.context.add_init_script("delete window.IdentityCredential")
        self.page.goto(self.origin + BASE + "/")
        self.page.get_by_role("button", name="Agree").click()
        prompt = self.page.get_by_role("region", name="Keystone ID One Tap")
        expect(prompt.get_by_role("link", name="Sign in to Keystone ID")).to_be_visible()
        prompt.get_by_role("button", name="Dismiss One Tap").click()
        dismissal = next(cookie for cookie in self.context.cookies() if cookie["name"] == "g_state")
        self.assertEqual("%7B%22i_l%22%3A1%7D", dismissal["value"])
        self.assertEqual(BASE, dismissal["path"])
        self.assertAlmostEqual(7200, dismissal["expires"] - time.time(), delta=10)
        self.page.reload()
        self.page.wait_for_function("typeof google?.accounts.id.prompt === 'function'")
        expect(prompt).to_have_count(0)

        self.context.clear_cookies(name="g_state")
        self.page.reload()
        prompt.get_by_role("link", name="Sign in to Keystone ID").click()
        self.page.get_by_role("button", name=re.compile("Bob")).click()
        choice = prompt.get_by_role("button", name="Continue as Bob")
        expect(choice).to_be_visible()
        self.page.evaluate("handleOneTapCredential({credential: 'invalid-test-token'})")
        expect(self.page.get_by_text("Invalid ID Token: Token not verified as issued by Google")).to_be_visible()
        self.observe_credential_callback()
        with self.observe_graphql("SignInWithOAuthMutation") as oauth_request:
            choice.click()
        self.assert_dashboard("Bob", path=IDP + "/gsi/fallback/issue")
        self.assert_oauth_request(oauth_request.value, "btn")
        print("Fallback link, 2 h dismissal, inline verifier error and Bob dashboard passed", flush=True)

    def test_redirect_and_workspace_profile(self):
        self.page.goto(self.origin + BASE + "/signin")
        self.page.get_by_role("button", name="Continue with Keystone ID").click()
        self.page.get_by_role("button", name=re.compile("Carol")).click()
        self.assert_dashboard("Carol")
        with self.observe_graphql("AccountQuery") as account_request:
            self.page.goto(self.origin + BASE + "/account")
        self.assert_persisted_request(account_request.value)
        name = self.page.get_by_role("textbox", name="Display name")
        name.fill("Carol Studio")
        with self.observe_graphql("UpdateProfile") as update_request:
            self.page.get_by_role("button", name="Save", exact=True).click()
        self.assert_persisted_request(update_request.value)
        expect(self.page.get_by_text("Display name saved.")).to_be_visible()
        self.page.reload()
        expect(name).to_have_value("Carol Studio")
        print("Redirect sign-in and persisted workspace profile update passed", flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
