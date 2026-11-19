import unittest
from urllib.parse import parse_qsl, urlsplit

from oauth_lab import CLIENT_ID, OAuthError, OAuthLab, opaque


def query(url):
    return dict(parse_qsl(urlsplit(url).query))


class OAuthLabTest(unittest.TestCase):
    def setUp(self):
        self.oauth = OAuthLab("https://app.test", "https://issuer.test", 18196)
        self.client_browser = opaque()
        self.issuer_browser = opaque()
        self.authorization = query(self.oauth.start(self.client_browser))

    def approve(self):
        grant = self.oauth.prepare_consent(self.authorization, self.issuer_browser)
        return query(self.oauth.complete_consent(grant, self.issuer_browser, "allow"))

    def test_redirect_uri_must_match_registration(self):
        authorization = {**self.authorization, "redirect_uri": "https://other.test/callback"}
        with self.assertRaises(OAuthError):
            self.oauth.prepare_consent(authorization, self.issuer_browser)

    def test_consent_is_browser_bound_and_one_time(self):
        grant = self.oauth.prepare_consent(self.authorization, self.issuer_browser)
        with self.assertRaises(OAuthError):
            self.oauth.complete_consent(grant, opaque(), "allow")
        result = query(self.oauth.complete_consent(grant, self.issuer_browser, "deny"))
        self.assertEqual(result["error"], "access_denied")
        with self.assertRaises(OAuthError):
            self.oauth.complete_consent(grant, self.issuer_browser, "allow")

    def test_callback_state_is_browser_bound_and_used_once(self):
        response = {"state": self.authorization["state"], "error": "access_denied"}
        with self.assertRaises(OAuthError):
            self.oauth.complete_callback(response, opaque())
        self.assertFalse(self.oauth.complete_callback(response, self.client_browser))
        with self.assertRaises(OAuthError):
            self.oauth.complete_callback(response, self.client_browser)

    def test_exchange_requires_client_authentication_and_matching_pkce(self):
        callback = self.approve()
        _, verifier = self.oauth.transactions.get(callback["state"])
        request = {
            "client_id": CLIENT_ID, "client_secret": self.oauth.client_secret,
            "grant_type": "authorization_code", "code": callback["code"],
            "redirect_uri": self.oauth.callback, "code_verifier": verifier,
        }
        with self.assertRaisesRegex(OAuthError, "invalid_client"):
            self.oauth.exchange({**request, "client_secret": opaque()})
        with self.assertRaisesRegex(OAuthError, "invalid_grant"):
            self.oauth.exchange({**request, "code_verifier": opaque()})
        with self.assertRaisesRegex(OAuthError, "invalid_grant"):
            self.oauth.exchange({**request, "redirect_uri": "https://other.test/callback"})
        response = self.oauth.exchange(request)
        self.assertEqual(response["token_type"], "Bearer")
        self.assertIsNotNone(self.oauth.tokens.get(response["access_token"]))
        with self.assertRaisesRegex(OAuthError, "invalid_grant"):
            self.oauth.exchange(request)


if __name__ == "__main__":
    unittest.main()
