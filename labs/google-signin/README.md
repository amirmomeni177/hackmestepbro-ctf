# Lumora sign-in reference lab

Lumora, its example workspace and customers, and Keystone ID are fictional. The lab has no flag. It demonstrates a Rails-style redirect flow using the stock OmniAuth Google OAuth2 strategy and One Tap using the browser’s FedCM API with a local identity provider.

## Run

Use system Ruby 3.3. From this directory, run:

```sh
bundle config set --local path vendor/bundle
bundle install
./start.sh
```

Puma runs as one process on `127.0.0.1`, port `18320` by default. Set `PORT` to change the port and `PUBLIC_ORIGIN` to set the browser-facing HTTPS origin. The default public page is `https://ctf.hackmestepbro.com/labs/google-signin/`.

In the nginx HTTPS server block, preserve the request path, host, and HTTPS scheme when proxying to Puma. Use the same upstream port as `PORT`.

```nginx
location /labs/google-signin/ {
    client_max_body_size 16k;
    proxy_pass http://127.0.0.1:18320;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto https;
}
```

The first start creates `data/secret`, `data/client.json`, `data/idp-key.pem`, `data/idp-accounts.json`, `data/idp-approvals.json`, and `data/users.json`. The session secret, generic client credentials, RSA-2048 key, numeric subjects, One Tap approvals, and relying-party users persist across restarts. Authorization codes expire after ten minutes and can be exchanged once. Access tokens and ID tokens expire after one hour. The redirect flow keeps issued codes and token lookup records in memory.

The chooser offers `alice@lab.test`, `bob@lab.test`, and `carol@lab.test`. Select an account to continue the sign-in flow.

## Screens

- The signed-out home page introduces Lumora with a sample board, fictional customers, product features, and static pricing.
- The sign-in page offers Keystone ID and shows the disabled email sign-in option.
- The signed-in home page shows the workspace dashboard, recent boards, and activity. The avatar menu provides account settings, account switching, and sign-out.
- Account settings show the signed-in profile, connected Keystone ID subject, and current session. The display name form requires JavaScript.
- Keystone ID shows the account chooser, requested scopes, and themed authorization errors for clients that request HTML.

Every HTML screen links back to the CTF library in its lab notice. Both themes use self-hosted styles, SVGs, and the bundled Instrument Sans and Instrument Serif fonts. The menus work without JavaScript.

## Routes

All paths below are relative to `/labs/google-signin`.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/` | Show Lumora marketing when signed out or the dashboard when signed in. |
| GET | `/signin` | Show the Keystone ID sign-in form and any sign-in error. |
| GET | `/account` | Show account settings or redirect to `/signin` when signed out. |
| GET | `/users/auth/google_oauth2` | Return `405 Method Not Allowed` with `Allow: POST`. |
| POST | `/users/auth/google_oauth2` | Start OmniAuth with a Rack::Protection authenticity token. |
| GET | `/users/auth/google_oauth2/callback` | Complete the code flow and return to the home page. |
| GET | `/users/auth/failure` | Forward the OmniAuth `message` to the home page as `error`, with `strategy=google_oauth2`. |
| GET | `/me` | Return `signed_in` and the user’s `id`, `email`, and `name`. The user is `null` when signed out. |
| POST | `/graphql` | Execute a raw or persisted GraphQL operation from JSON or URL-encoded form data. |
| GET | `/graphql` | Execute a supplied query, return 403 HTML for mutations, or return 405 with `Allow: POST` for a bare request. |
| GET | `/graphql/schema` | Serve the GraphQL schema as plain-text SDL. |
| GET | `/persisted.json` | Serve the operation-name-to-ID manifest generated at boot. |
| GET | `/privacy`, `/terms` | Show the policy documents linked from FedCM client metadata. |
| POST | `/signout` | Clear the session. Requires an authenticity token. |
| GET | `/idp/o/oauth2/auth` | Validate the client and exact redirect URI, then choose an account and return a code with the original state. |
| POST | `/idp/token` | Exchange a code using client credentials supplied by HTTP Basic or form fields. |
| GET | `/idp/oauth2/v3/userinfo` | Return the profile for a bearer access token. |
| GET, POST | `/idp/oauth2/v3/tokeninfo` | Look up an issued `access_token` or `id_token` by query or form parameter. |
| GET | `/idp/oauth2/v3/certs` | Return the public signing key as JWKS. |
| GET, POST | `/idp/signin` | Show the Keystone ID sign-in page or add a selected account to the Keystone session. |
| POST | `/idp/signout` | Clear the Keystone ID accounts and send `Set-Login: logged-out`. |
| GET | `/idp/gsi/client` | Serve the GIS-shaped One Tap client library. |
| GET | `/idp/gsi/fedcm.json` | Serve the Keystone FedCM configuration. |
| GET | `/idp/gsi/fedcm/signin` | Show the sign-in page for the browser’s FedCM login URL. |
| GET | `/idp/gsi/fedcm/listaccounts` | List accounts in the Keystone session for a native FedCM request. |
| GET | `/idp/gsi/fedcm/clientmetadata` | Return policy URLs for the registered client. |
| POST | `/idp/gsi/fedcm/issue` | Issue an ID token to the registered RP origin for a signed-in account. |
| POST | `/idp/gsi/fedcm/metrics` | Acknowledge native FedCM metrics with HTTP 204. |
| POST | `/idp/gsi/fedcm/revoke` | Remove a client approval from the selected Keystone account. |
| GET | `/idp/gsi/status` | Return the Keystone signed-in status for the registered client. |
| GET, POST | `/idp/gsi/fallback/listaccounts`, `/idp/gsi/fallback/issue` | List accounts by GET and issue a token by POST from the same-origin One Tap client. |
| GET | `/idp/gsi-static/keystone.svg`, `/idp/gsi-static/avatar/:subject.svg` | Serve Keystone branding and account avatars. |
| GET | `/idp/.well-known/web-identity` | Document the provider and endpoint URLs under the lab prefix. |
| GET | `/assets/*` | Serve local scripts, styles, fonts, and SVG marks. |

OmniAuth failures redirect directly to the home page with the error and strategy query parameters. The session cookie is Secure, HttpOnly, SameSite=Lax, and scoped to `/labs/google-signin`.

## GraphQL API

POST JSON to `/labs/google-signin/graphql` with a raw `query` or an `extensions.operationId` from `persisted.json`, plus optional `variables` and `operationName`. The browser uses IDs of the form `Lumora/<SHA-256 of the query>`. URL-encoded forms use `extensions[operationId]` and a JSON string for `variables`. A `text/plain` body supplies no parameters. Unresolved requests return HTTP 200 with `{"errors":[{"message":"No query string was present"}]}`. Request bodies over 16 KiB receive HTTP 413. Introspection has a depth limit of 10 and a complexity limit of 200. [Schema SDL](/labs/google-signin/graphql/schema)

Authentication uses the existing Lumora session cookie. When signed out, `currentUser` is `null` and protected fields return `extensions.code: UNAUTHENTICATED`. Signed-in users can look up their workspace’s boards by slug. Other slugs return `null`.

The browser copies the `csrftoken` cookie into `X-CSRF-Token`. All GraphQL mutations use Rails-style null-session semantics. A missing or wrong header runs the mutation with an empty, throwaway session. An OAuth mutation can return a user in its payload while the browser session stays signed out or retains its original user. Protected mutations such as `updateProfile` and `signOut` report `UNAUTHENTICATED` in the throwaway session. A valid header permits session changes to persist. `updateProfile` trims the display name and saves names of 1 to 60 characters to `data/users.json`. The dashboard and account settings also render on the server for browsers with JavaScript disabled.

## One Tap and FedCM

Sign in to Keystone ID at `/idp/signin` or use the existing redirect chooser. Keystone records one or more accounts in a Secure, HttpOnly, SameSite=None cookie scoped to the IdP and signals its login state through `Set-Login`. Eligible, signed-out Lumora pages show an **Agree** button. Once `trackingConsent=true` is stored, Lumora mounts `g_id_onload` and loads the Keystone client with the page’s CSP nonce. The RP sends no nonce from its HTML configuration.

The client calls `navigator.credentials.get()` with a FedCM identity provider. If the browser lacks FedCM or rejects the request, a Keystone prompt offers signed-in accounts or a link to Keystone sign-in. The fallback uses credentialed, same-origin fetches on the companion endpoints, with an explicit same-origin Fetch Metadata check and a custom request header. Browser JavaScript cannot set the native endpoints’ required `Sec-Fetch-Dest: webidentity` header. Dismissing the fallback sets `g_state={"i_l":1}` for two hours. [FedCM specification](https://www.w3.org/TR/fedcm-1/#sec-fetch-dest-header)

Both paths call `handleOneTapCredential`, which sends the token to the persisted `SignInWithOAuthMutation` with provider `GOOGLE_OAUTH2` and platform `WEB`. The unmodified `google-id-token` gem receives the local X.509 certificate through its public `x509_cert` option. The certificate and the redirect JWKS contain the same public key. The gem checks the audience, issuer, signature and expiration. Both flows map the verified subject to the same Lumora account. `FACEBOOK` and `APPLE` return an unsupported-provider error.

On 2026-11-20, Google’s FedCM config returned HTTP 200. It gave the paths `/gsi/fedcm/issue`, `/gsi/fedcm/listaccounts`, `/gsi/fedcm/clientmetadata`, `/gsi/fedcm/signin`, `/gsi/fedcm/metrics` and `/gsi/fedcm/revoke`. The mock rebases these under `/idp` and keeps the config field names and aliases. Keystone supplies its own branding and includes `label_hints: ["n"]` on accounts to match the mirrored config label. [Google FedCM config](https://accounts.google.com/gsi/fedcm.json)

Google’s requested well-known URL at `accounts.google.com` returned HTTP 404. The registrable-domain URL at `google.com` redirected to `www.google.com`, which returned HTTP 200 with `provider_urls`, `accounts_endpoint` and `login_url`. The lab serves those fields below its IdP prefix for documentation. [Requested well-known URL](https://accounts.google.com/.well-known/web-identity) · [Google’s published well-known JSON](https://www.google.com/.well-known/web-identity)

## Provider transport

`client_options[:authorize_url]` sends the browser to the public mock chooser. The remaining strategy URLs keep their defaults. The strategy’s `client_options[:connection_build]` inserts `Lab::MockTransport` first in the OAuth2 client’s Faraday stack. It rewrites requests for `accounts.google.com`, `oauth2.googleapis.com`, and `www.googleapis.com` to `http://127.0.0.1:PORT/labs/google-signin/idp`, preserving the original path and query.

In `omniauth-google-oauth2` 1.2.3, token exchange, userinfo, tokeninfo, and JWKS all use that OAuth2 client. The Faraday hook covers every server-side provider request.

## Locked versions

| Gem | Version |
| --- | --- |
| sinatra | 4.2.2 |
| puma | 8.1.2 |
| rack-session | 2.1.2 |
| omniauth | 2.4.2 |
| omniauth-oauth2 | 1.10.1 |
| omniauth-google-oauth2 | 1.2.3 |
| oauth2 | 2.1.0 |
| jwt | 3.3.0 |
| google-id-token | 1.4.2 |
| rack-protection | 4.2.2 |
| graphql | 2.6.16 |
| minitest | 5.27.0 |

## Verification

```sh
bundle exec ruby test/flow_test.rb
```

The suite starts Puma on a free loopback port with isolated data and simulates the headers nginx forwards over HTTPS.

```text
30 runs, 1626 assertions, 0 failures, 0 errors, 0 skips
```

The browser suite ran with Playwright 1.65.2 and Chromium 156.0.8078.79. It used an isolated Puma process and a loopback HTTPS proxy with the lab hostname and an ephemeral port. To run it with the local Chromium installation, use the following command.

```sh
browser_home=/root/labs-build/.venv-browser
LUMORA_CHROMIUM="$browser_home/debian/usr/lib/chromium/chromium" \
LD_LIBRARY_PATH="$browser_home/debian/usr/lib/x86_64-linux-gnu" \
"$browser_home/bin/python" test/browser_test.py
```

```text
Ran 3 tests in 11.919s
OK
```

Chromium opened the native `AccountChooser`. CDP `FedCm.selectAccount` returned a credential and the persisted GraphQL sign-in reached Alice’s dashboard. The fallback test reached Bob’s dashboard and verified the two-hour dismissal cookie and inline verifier errors. The redirect test reached Carol’s dashboard and saved a profile change using a persisted operation.

For the same-origin RP and IdP, Chromium requested `https://hackmestepbro.com/.well-known/web-identity` and got HTTP 404 from the local test proxy. It skipped enforcement of that response and completed FedCM. The proxy and Chromium NetLog confirmed the root request. The browser used no FedCM override flags. [Chromium well-known handling](https://chromium.googlesource.com/chromium/src/+/b8ec1c98a1f6f7ce512128d7a3776c534e8b72f0/content/browser/webid/config_fetcher.cc)

`diff -qr` found zero differences between the installed `google-id-token` 1.4.2 `lib/` and the official release package’s `lib/`. It was the only added gem. [Official gem package](https://rubygems.org/downloads/google-id-token-1.4.2.gem)
