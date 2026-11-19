import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

TRANSACTION_AGE = 300
CODE_AGE = 120
TOKEN_AGE = 300
CLIENT_ID = "afterframe-studio"
SCOPE = "instagram_business_basic"
PROFILE = {"user_id": "demo-riley", "username": "riley.frames"}
AUTHORIZE_PATH = "/oauth/authorize"
CALLBACK_PATH = "/oauth/callback"
TOKEN_PATH = "/oauth/token"
PROFILE_PATH = "/oauth/me"


class OAuthError(Exception):
    pass


def opaque():
    return secrets.token_urlsafe(32)


def valid_secret(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{43}", value or ""))


def s256(verifier):
    checksum = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(checksum).rstrip(b"=").decode("ascii")


class ExpiringRecords:
    def __init__(self, lifetime):
        self.lifetime = lifetime
        self.records = {}
        self.lock = threading.Lock()

    def issue(self, value):
        now = time.monotonic()
        with self.lock:
            self.records = {
                key: record for key, record in self.records.items() if record[0] > now
            }
            if len(self.records) >= 4096:
                raise OAuthError("Temporarily busy")
            key = opaque()
            self.records[key] = (now + self.lifetime, value)
            return key

    def get(self, key, accept=None, consume=False):
        if not valid_secret(key):
            return None
        with self.lock:
            record = self.records.get(key)
            if record is None:
                return None
            expiry, value = record
            if expiry <= time.monotonic():
                del self.records[key]
                return None
            if accept is not None and not accept(value):
                return None
            if consume:
                del self.records[key]
            return value


class OAuthLab:
    def __init__(self, app_origin, issuer_origin, port):
        self.app_origin = app_origin
        self.issuer_origin = issuer_origin
        self.app_host = urlsplit(app_origin).netloc
        self.issuer_host = urlsplit(issuer_origin).netloc
        self.callback = app_origin + CALLBACK_PATH
        self.loopback = f"http://127.0.0.1:{port}"
        self.client_secret = opaque()
        self.internal_secret = opaque()
        self.transactions = ExpiringRecords(TRANSACTION_AGE)
        self.grants = ExpiringRecords(TRANSACTION_AGE)
        self.codes = ExpiringRecords(CODE_AGE)
        self.tokens = ExpiringRecords(TOKEN_AGE)

    def start(self, browser):
        verifier = opaque()
        state = self.transactions.issue((browser, verifier))
        params = {
            "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": self.callback,
            "scope": SCOPE, "state": state, "code_challenge": s256(verifier),
            "code_challenge_method": "S256",
        }
        return self.issuer_origin + AUTHORIZE_PATH + "?" + urlencode(params)

    def prepare_consent(self, params, browser):
        if (
            params.get("client_id") != CLIENT_ID
            or params.get("response_type") != "code"
            or params.get("redirect_uri") != self.callback
            or params.get("scope") != SCOPE
            or params.get("code_challenge_method") != "S256"
            or not valid_secret(params.get("state"))
            or not valid_secret(params.get("code_challenge"))
        ):
            raise OAuthError("Invalid authorization request")
        return self.grants.issue((browser, params["state"], params["code_challenge"]))

    def complete_consent(self, grant, browser, decision):
        if not valid_secret(browser) or decision not in {"allow", "deny"}:
            raise OAuthError("Invalid consent")
        approval = self.grants.get(grant, lambda item: item[0] == browser, consume=True)
        if approval is None:
            raise OAuthError("Consent expired")
        _, state, challenge = approval
        result = {"state": state}
        if decision == "allow":
            result["code"] = self.codes.issue(challenge)
        else:
            result["error"] = "access_denied"
        return self.callback + "?" + urlencode(result)

    def exchange(self, params):
        if (
            params.get("client_id") != CLIENT_ID
            or not valid_secret(params.get("client_secret"))
            or not hmac.compare_digest(params["client_secret"], self.client_secret)
        ):
            raise OAuthError("invalid_client")
        verifier = params.get("code_verifier")
        if (
            params.get("grant_type") != "authorization_code"
            or params.get("redirect_uri") != self.callback
            or not valid_secret(verifier)
        ):
            raise OAuthError("invalid_grant")
        challenge = s256(verifier)
        verified = self.codes.get(
            params.get("code"), lambda expected: hmac.compare_digest(expected, challenge), consume=True
        )
        if verified is None:
            raise OAuthError("invalid_grant")
        token = self.tokens.issue(PROFILE)
        return {"access_token": token, "token_type": "Bearer", "expires_in": TOKEN_AGE, "scope": SCOPE}

    def complete_callback(self, params, browser):
        if not valid_secret(browser):
            raise OAuthError("Start sign-in again")
        transaction = self.transactions.get(
            params.get("state"), lambda item: item[0] == browser, consume=True
        )
        if transaction is None:
            raise OAuthError("Start sign-in again")
        if params.get("error") == "access_denied":
            return False
        code = params.get("code")
        if not valid_secret(code):
            raise OAuthError("Start sign-in again")
        _, verifier = transaction
        token = self._request(TOKEN_PATH, data={
            "client_id": CLIENT_ID, "client_secret": self.client_secret,
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": self.callback, "code_verifier": verifier,
        })
        bearer = token.get("access_token")
        if token.get("scope") != SCOPE or not valid_secret(bearer):
            raise OAuthError("Invalid token response")
        profile = self._request(PROFILE_PATH, bearer=bearer)
        if profile != PROFILE:
            raise OAuthError("Unexpected demo account")
        return True

    def _request(self, path, data=None, bearer=None):
        request = Request(
            self.loopback + path, data=urlencode(data).encode("ascii") if data else None,
            headers={"Host": self.issuer_host, "X-Afterframe-Internal": self.internal_secret},
        )
        if bearer:
            request.add_header("Authorization", "Bearer " + bearer)
        try:
            opener = build_opener(ProxyHandler({}))
            with opener.open(request, timeout=5) as response:
                result = json.loads(response.read(8192))
        except (URLError, OSError, ValueError) as error:
            raise OAuthError("Provider exchange failed") from error
        if not isinstance(result, dict):
            raise OAuthError("Invalid provider response")
        return result
