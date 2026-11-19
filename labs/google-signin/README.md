# Google sign-in reference lab

This reference lab — no flag — shows how a Rails-style API signs users in with the stock OmniAuth Google OAuth2 strategy and a local mock identity provider.

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
    proxy_pass http://127.0.0.1:18320;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto https;
}
```

The first start creates `data/secret`, `data/client.json`, `data/idp-key.pem`, `data/idp-accounts.json`, and `data/users.json`. The session secret, generic client credentials, RSA-2048 key, numeric subjects, and relying-party users persist across restarts. Authorization codes expire after ten minutes and can be exchanged once. Access tokens and ID tokens expire after one hour. The mock keeps issued codes and tokens in memory.

The chooser offers `alice@lab.test`, `bob@lab.test`, and `carol@lab.test`. Select an account to continue the sign-in flow.

## Routes

All paths below are relative to `/labs/google-signin`.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/` | Show sign-in status and the session forms. |
| POST | `/users/auth/google_oauth2` | Start OmniAuth with a Rack::Protection authenticity token. |
| GET | `/users/auth/google_oauth2/callback` | Complete the code flow and return to the home page. |
| GET | `/users/auth/failure` | Forward the OmniAuth `message` to the home page as `error`, with `strategy=google_oauth2`. |
| GET | `/me` | Return `signed_in` and the user’s `id`, `email`, and `name`. The user is `null` when signed out. |
| POST | `/signout` | Clear the session. Requires an authenticity token. |
| GET | `/idp/o/oauth2/auth` | Validate the client and exact redirect URI, then choose an account and return a code with the original state. |
| POST | `/idp/token` | Exchange a code using client credentials supplied by HTTP Basic or form fields. |
| GET | `/idp/oauth2/v3/userinfo` | Return the profile for a bearer access token. |
| GET, POST | `/idp/oauth2/v3/tokeninfo` | Look up an issued `access_token` or `id_token` by query or form parameter. |
| GET | `/idp/oauth2/v3/certs` | Return the public signing key as JWKS. |

OmniAuth failures redirect directly to the home page with the error and strategy query parameters. The session cookie is Secure, HttpOnly, SameSite=Lax, and scoped to `/labs/google-signin`.

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
| rack-protection | 4.2.2 |
| minitest | 5.27.0 |

## Verification

```sh
bundle exec ruby test/flow_test.rb
```

The suite starts Puma on a free loopback port with isolated data and simulates the headers nginx forwards over HTTPS.

```text
6 runs, 225 assertions, 0 failures, 0 errors, 0 skips
```
