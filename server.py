import hashlib
import hmac
import json
import os
import secrets
import time
from html import escape
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PUBLIC = Path(__file__).resolve().parent / "public"
FLAG = os.environ.get("AFTERFRAME_FLAG") or f"CTF{{{secrets.token_hex(16)}}}"
SESSION_KEY = secrets.token_bytes(32)
SESSION_AGE = 12 * 60 * 60
COOKIE = "__Host-afterframe-demo"

VIEWS = {
    "/studio": "Overview",
    "/studio/media": "Media library",
    "/studio/analytics": "Activity",
    "/studio/settings/connection": "Connections",
    "/studio/help": "Help center",
}
CHALLENGE_PATH = "/challenges/the-wrong-window"
PAGES = {CHALLENGE_PATH: "challenge.html", "/connect/instagram": "connect.html", "/case": "case.html"}
CATALOG = json.loads((PUBLIC.parent / "challenges.json").read_text(encoding="utf-8"))
ASSETS = {
    "site.2.css": "text/css; charset=utf-8",
    "auth.3.js": "text/javascript; charset=utf-8",
    "studio.3.js": "text/javascript; charset=utf-8",
    "case.4.js": "text/javascript; charset=utf-8",
    "library.2.css": "text/css; charset=utf-8",
    "library.1.js": "text/javascript; charset=utf-8",
    "terminal.1.webp": "image/webp",
    "icon.1.svg": "image/svg+xml",
}
ASSETS.update({file.name: "font/woff2" for file in (PUBLIC / "assets").glob("*.woff2")})

MEDIA = [
    {"name": "Night signals", "kind": "Reel", "date": "Nov 17", "status": "Published", "tone": "violet"},
    {"name": "In transit", "kind": "Carousel", "date": "Nov 14", "status": "Published", "tone": "rose"},
    {"name": "Window seat", "kind": "Photo", "date": "Nov 11", "status": "Draft", "tone": "blue"},
    {"name": "Darkroom notes", "kind": "Photo", "date": "Nov 8", "status": "Published", "tone": "green"},
]
ARTICLES = [
    {"title": "Manage a connected account", "body": "Connections shows which demo creator is linked to this studio. Sign out from the sidebar to end your demo session."},
    {"title": "Read the activity report", "body": "Activity lists the studio’s sample audience events. Filter by status to inspect reviewed or queued events."},
    {"title": "Find media drafts", "body": "Open Media library and switch the view to Draft to see unpublished items."},
]
PRODUCT_DATA = {
    "/api/studio/summary": {"posts": 12, "reach": 18420, "review": 2, "media": MEDIA[:3]},
    "/api/media/items": {"items": MEDIA},
    "/api/analytics/overview": {"reach": 18420, "views": 27654, "saves": 643, "events": [
        {"time": "11:04", "name": "Weekly reach snapshot", "source": "Audience report", "status": "Reviewed"},
        {"time": "10:21", "name": "Sample event AF-104", "source": "Activity widget", "status": "Reviewed"},
        {"time": "10:20", "name": "Sample event AF-103", "source": "Activity widget", "status": "Reviewed"},
        {"time": "09:18", "name": "Draft campaign check", "source": "Media library", "status": "Queued"},
        {"time": "08:42", "name": "Creator export", "source": "Audience report", "status": "Queued"},
    ]},
    "/api/settings/account": {"displayName": "Riley Lane", "handle": "@riley.frames", "provider": "Instagram", "status": "Connected"},
    "/api/support/articles": {"articles": ARTICLES},
}

# Historical, fictional receipts. They are data only and cannot update the studio.
RECORDINGS = {
    "/api/media/delivery": ("media.preview", "preview.frame", "Preview state updated", "Ignored", "No preview update"),
    "/api/analytics/diagnostics": ("activity.review", "insights.frame", "Sample event AF-103 approved", "Applied", "Sample event AF-104 approved"),
    "/api/settings/delivery": ("connection.ready", "identity.popup", "Connection indicator updated", "Ignored", "No connection update"),
    "/api/support/delivery": ("help.ready", "support.frame", "Help panel initialized", "Ignored", "No help panel update"),
}


def recording(item):
    event, expected, effect, comparison_result, comparison_effect = item
    def receipt(sender, outcome, action, timestamp):
        return {"time": timestamp, "event": event, "origin": "https://widgets.afterframe.test",
                "window": sender, "disposition": outcome, "effect": action}
    return {"expectedWindow": expected, "deliveries": [
        receipt(expected, "Applied", effect, "2026-11-19T10:20:43Z"),
        receipt("status.frame", comparison_result, comparison_effect, "2026-11-19T10:21:06Z"),
    ]}


def sign(value):
    return hmac.new(SESSION_KEY, value.encode("ascii"), hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Afterframe"
    sys_version = ""

    def log_message(self, *_):
        pass

    def reply(self, status, content, content_type, cache="no-store", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "img-src 'self'; font-src 'self'; connect-src 'self'; "
                         "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        if self.close_connection:
            self.send_header("Connection", "close")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def json_reply(self, status, data, headers=()):
        self.reply(status, json.dumps(data, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8", headers=headers)

    def signed_in(self):
        try:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            cookie = cookies.get(COOKIE)
            if not cookie:
                return False
            issued, nonce, signature = cookie.value.split(".")
            if len(nonce) != 24 or len(signature) != 64 or len(issued) != 10:
                return False
            age = int(time.time()) - int(issued)
            return 0 <= age < SESSION_AGE and hmac.compare_digest(signature, sign(f"{issued}.{nonce}"))
        except (ValueError, CookieError, TypeError):
            return False

    def session_cookie(self, clear=False):
        value = "" if clear else f"{int(time.time())}.{secrets.token_hex(12)}"
        if value:
            value = f"{value}.{sign(value)}"
        age = 0 if clear else SESSION_AGE
        return f"{COOKIE}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Lax"

    def authenticated_post(self):
        host = self.headers.get("Host")
        origin = self.headers.get("Origin")
        if not host or not origin:
            return False
        if origin == f"https://{host}":
            return True
        return (host in {"127.0.0.1", "localhost"} or host.startswith(("127.0.0.1:", "localhost:"))) and origin == f"http://{host}"

    def html(self, name):
        self.reply(200, (PUBLIC / name).read_bytes(), "text/html; charset=utf-8")

    def library(self):
        cards = []
        for challenge in CATALOG:
            metadata = {key: escape(value) for key, value in challenge.items()}
            search = escape(f"{challenge['name']} {challenge['category']} {challenge['difficulty']}".lower())
            cards.append(f"""
              <a class="challenge-card" href="{metadata['path']}" data-challenge="{metadata['id']}" data-search="{search}">
                <img class="challenge-image" src="{metadata['image']}" alt="" width="1050" height="1312">
                <div class="challenge-content">
                  <div class="challenge-meta"><span>{metadata['category']}</span><span>{metadata['difficulty']}</span></div>
                  <h3>{metadata['name']}</h3>
                  <p>{metadata['description']}</p>
                  <span class="challenge-action">Play challenge</span>
                </div>
              </a>
            """)
        count = len(cards)
        label = "1 challenge" if count == 1 else f"{count} challenges"
        template = (PUBLIC / "index.html").read_text(encoding="utf-8")
        html = template.replace("{{COUNT}}", label).replace("{{CARDS}}", "\n".join(cards))
        self.reply(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self.library()
            return
        if path == CHALLENGE_PATH + "/":
            self.reply(308, b"", "text/plain; charset=utf-8", headers=[("Location", CHALLENGE_PATH)])
            return
        if path in PAGES:
            self.html(PAGES[path])
            return
        if path in VIEWS:
            if not self.signed_in():
                self.reply(303, b"", "text/plain; charset=utf-8", headers=[("Location", CHALLENGE_PATH)])
                return
            self.html("studio.html")
            return
        if path in PRODUCT_DATA or path in RECORDINGS:
            if not self.signed_in():
                self.json_reply(401, {"message": "Connect the demo account to open its studio data."})
                return
            content = PRODUCT_DATA[path] if path in PRODUCT_DATA else recording(RECORDINGS[path])
            self.json_reply(200, content)
            return
        if path.startswith("/assets/"):
            name = path.removeprefix("/assets/")
            if name in ASSETS:
                self.reply(200, (PUBLIC / "assets" / name).read_bytes(),
                           ASSETS[name], "public, max-age=86400")
                return
        self.json_reply(404, {"message": "Route not found."})

    def do_POST(self):
        self.close_connection = True
        path = urlsplit(self.path).path
        if path not in {"/api/demo/session", "/api/demo/signout", "/api/verify"}:
            self.json_reply(404, {"message": "Route not found."})
            return
        if not self.authenticated_post():
            self.json_reply(403, {"message": "Use the Afterframe site to submit this action."})
            return
        if self.headers.get_content_type() != "application/json":
            self.json_reply(415, {"message": "Send an application/json body."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 2048:
                raise ValueError
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeError):
            self.json_reply(400, {"message": "Send a short JSON object."})
            return
        if path == "/api/demo/session":
            if body.get("account") != "riley-frames":
                self.json_reply(400, {"message": "Choose the available demo account."})
                return
            self.json_reply(200, {"connected": True}, [("Set-Cookie", self.session_cookie())])
            return
        if path == "/api/demo/signout":
            self.json_reply(200, {"connected": False}, [("Set-Cookie", self.session_cookie(clear=True))])
            return
        route = body.get("route")
        if isinstance(route, str):
            try:
                reference = urlsplit(route.strip())
                if not reference.netloc or reference.netloc == self.headers.get("Host"):
                    route = reference.path.rstrip("/")
            except ValueError:
                route = None
        correct = (route in ("/studio/analytics", "/api/analytics/diagnostics")
                   and body.get("control") == "window" and body.get("effect") == "event")
        if correct:
            self.json_reply(200, {"solved": True, "flag": FLAG})
            return
        self.json_reply(200, {"solved": False, "message": "That finding does not match the recorded incident."})


if __name__ == "__main__":
    bind = "127.0.0.1"
    port = int(os.environ.get("AFTERFRAME_PORT", "18196"))
    with ThreadingHTTPServer((bind, port), Handler) as server:
        print(f"Afterframe is ready at http://{bind}:{port}", flush=True)
        server.serve_forever()
