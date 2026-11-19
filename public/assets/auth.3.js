const origin = window.location.origin;
const page = document.body.dataset.page;
const get = (id) => document.getElementById(id);

if (page === "landing") {
  let popup = null;
  let state = "";
  let poll;
  const status = get("login-status");

  const connect = get("connect");

  connect.addEventListener("click", () => {
    if (popup && !popup.closed) {
      popup.focus();
      return;
    }
    window.clearInterval(poll);
    state = crypto.randomUUID();
    const url = new URL("/connect/instagram", origin);
    url.searchParams.set("state", state);
    popup = window.open(url.href, "afterframe-demo-connect", "popup,width=480,height=650");
    if (!popup) {
      window.location.assign(url.href);
      return;
    }
    status.hidden = false;
    status.textContent = "Finish the demo connection in the popup.";
    poll = window.setInterval(() => {
      if (popup.closed) {
        window.clearInterval(poll);
        popup = null;
        state = "";
        status.hidden = true;
      }
    }, 350);
  });

  window.addEventListener("message", (event) => {
    if (!popup || !state || event.origin !== origin || event.source !== popup) return;
    if (event.data?.type !== "afterframe.demo.confirmed" || event.data.state !== state) return;
    window.clearInterval(poll);
    state = "";
    popup.close();
    window.location.assign("/studio");
  });
  connect.disabled = false;
}

if (page === "connect") {
  const state = new URL(window.location.href).searchParams.get("state");
  const opener = window.opener;
  const authorize = get("authorize");
  const status = get("connect-status");

  authorize.addEventListener("click", async () => {
    authorize.disabled = true;
    status.hidden = true;
    try {
      const response = await fetch("/api/demo/session", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({account: "riley-frames"}),
      });
      if (!response.ok) throw new Error("Connection unavailable");
      if (opener && !opener.closed && /^[a-f0-9-]{36}$/.test(state ?? "")) {
        opener.postMessage({type: "afterframe.demo.confirmed", state}, origin);
        return;
      }
      window.location.assign("/studio");
    } catch {
      status.hidden = false;
      status.textContent = "The demo connection is unavailable. Try again.";
      authorize.disabled = false;
    }
  });

  get("cancel").addEventListener("click", (event) => {
    if (opener && !opener.closed) {
      event.preventDefault();
      opener.focus();
      window.close();
    }
  });
  authorize.disabled = false;
}
