# HackMeStepBro CTF Library

Play on the [live CTF library](https://ctf.hackmestepbro.com/). The first challenge, **The Wrong Window**, is set in a fictional creator studio. Players sign in as a demo creator, explore studio features, and use network responses to compare synthetic delivery receipts. The separate challenge brief accepts a page or API reference and grades the finding on the server.

The demo popup uses live same-origin messaging. The recorded incident does not execute messages, alter accounts, or contact Instagram.

## Challenge library

The homepage lists the challenges in `challenges.json`. To list another challenge, add an entry with a unique ID, name, launch path, category, difficulty, description, and cover image. The launch path must lead to that challenge’s own page. Serve custom covers from the app’s assets or reuse the existing cover. Restart the app after editing the catalog.

Players see their solved status in the browser where they captured the flag. The library saves only a solved marker.

## Run locally

With Python 3.9 or later, run `python3 server.py` and open [localhost:18196](http://127.0.0.1:18196). Set `AFTERFRAME_PORT` to change the port. The server binds to loopback and generates a flag at startup unless `AFTERFRAME_FLAG` is supplied.

The service and proxy examples in `deploy/` are for [ctf.hackmestepbro.com](https://ctf.hackmestepbro.com). The source includes the answer checker and contains spoilers.

## Inspiration

- [Youssef Sammouda’s Instagram and Meta Pixel write-up](https://ysamm.com/uncategorized/2026/01/16/leaking-fbevents-ato.html)
- [PortSwigger Web Security Academy’s web messaging labs](https://portswigger.net/web-security/dom-based/web-message-manipulation)
