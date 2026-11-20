# HackMeStepBro CTF Library

Play on the [live CTF library](https://ctf.hackmestepbro.com/). The first challenge, **The Wrong Window**, is set in a fictional creator studio. Players sign in as a demo creator, explore studio features, and use network responses to compare synthetic delivery receipts. The separate challenge brief accepts a page or API reference and grades the finding on the server.

The demo uses an authorization-code flow with a separate sandbox issuer, consent, state, S256 PKCE, and a server-side code exchange. Read the [Instagram and Facebook OAuth research](docs/meta-oauth-research.md) for a comparison with Meta’s actual products. The recorded incident uses synthetic evidence.

## Challenge library

The homepage lists the challenges in `challenges.json`. To list another challenge, add an entry with a unique ID, name, launch path, category, difficulty, description, and cover image. The launch path must lead to that challenge’s own page. Serve custom covers from the app’s assets or reuse the existing cover. Restart the app after editing the catalog.

Players see their solved status in the browser where they captured the flag. The library saves only a solved marker.

## Run locally

With Python 3.9 or later, run `python3 server.py` and open [localhost:18196](http://127.0.0.1:18196). Set `AFTERFRAME_PORT` to change the port. The server uses `127.0.0.1` for the app and `localhost` for the demo issuer on the same port. It generates a flag at startup unless `AFTERFRAME_FLAG` is supplied.

The service and proxy examples in `deploy/` configure the [CTF site](https://ctf.hackmestepbro.com) and its demo OAuth issuer at `oauth-lab.hackmestepbro.com`. Install `oauth-origins.conf` as a systemd drop-in when deploying both HTTPS hosts. The token and profile exchanges go over loopback. The source includes the answer checker and contains spoilers.

## Reference labs

Labs under `labs/` are study replicas, not challenges: they have no flag and no planted bug.

- [`labs/google-signin`](labs/google-signin/README.md) is Lumora, a fictional creative-workspace SaaS with "Continue with Keystone ID" sign-in and a GraphQL API (graphql-ruby 2.6.16, CSRF-protected mutations). Under the hood it runs the stock OmniAuth Google OAuth2 flow. The gems are pinned and unmodified: `omniauth` 2.4.2, `omniauth-oauth2` 1.10.1, `omniauth-google-oauth2` 1.2.3 and `oauth2` 2.1.0. They run against an in-lab mock identity provider. It is served at [ctf.hackmestepbro.com/labs/google-signin/](https://ctf.hackmestepbro.com/labs/google-signin/) by `deploy/google-signin-lab.service` on loopback port 18320, behind the `/labs/google-signin/` location in `deploy/ctf.hackmestepbro.com.nginx`.

## Inspiration

- [Youssef Sammouda’s Instagram and Meta Pixel write-up](https://ysamm.com/uncategorized/2026/01/16/leaking-fbevents-ato.html)
- [PortSwigger Web Security Academy’s web messaging labs](https://portswigger.net/web-security/dom-based/web-message-manipulation)
