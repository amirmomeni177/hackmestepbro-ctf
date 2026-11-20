(() => {
  const idp = new URL("../", document.currentScript.src).pathname.replace(/\/$/, "");
  const base = idp.slice(0, -"/idp".length);
  const configURL = new URL(idp + "/gsi/fedcm.json", location.origin).href;
  const fallbackOptions = {
    mode: "same-origin",
    credentials: "include",
    headers: { "X-Keystone-One-Tap": "1" }
  };
  let configuration;
  let request;
  let panel;

  function initialize(options) {
    cancel();
    configuration = { ...options };
  }

  function suppressed() {
    const cookie = document.cookie.split("; ").find(entry => entry.startsWith("g_state="));
    try {
      return Boolean(cookie && JSON.parse(decodeURIComponent(cookie.slice(8))).i_l);
    } catch {
      return false;
    }
  }

  function disableAutoSelect() {
    // Let the browser suppress automatic selection for native FedCM.
    navigator.credentials?.preventSilentAccess?.().catch(() => {});
    document.cookie = "g_state=" + encodeURIComponent(JSON.stringify({ i_l: 1 })) +
      "; Max-Age=7200; Path=" + base + "; Secure; SameSite=Lax";
  }

  function cancel() {
    request?.abort();
    request = undefined;
    panel?.remove();
    panel = undefined;
  }

  function deliver(options, credential, selectBy) {
    const callback = typeof options.callback === "function" ? options.callback : window[options.callback];
    cancel();
    callback?.({ credential, select_by: selectBy });
  }

  async function fallback(options, signal) {
    let accounts = [];
    try {
      const response = await fetch(idp + "/gsi/fallback/listaccounts", { ...fallbackOptions, signal });
      if (response.ok) ({ accounts } = await response.json());
    } catch {
      if (signal.aborted) return;
    }
    if (signal.aborted) return;

    panel = document.createElement("section");
    panel.className = "one-tap";
    panel.setAttribute("aria-label", "Keystone ID One Tap");
    const header = document.createElement("header");
    const icon = document.createElement("img");
    icon.src = idp + "/gsi-static/keystone.svg";
    icon.width = icon.height = 24;
    icon.alt = "";
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "one-tap-close";
    dismiss.setAttribute("aria-label", "Dismiss One Tap");
    dismiss.textContent = "×";
    dismiss.addEventListener("click", () => {
      disableAutoSelect();
      cancel();
    });
    header.append(icon, "Keystone ID", dismiss);
    panel.append(header);

    const status = document.createElement("p");
    status.setAttribute("role", "alert");
    const buttons = accounts.map(account => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "one-tap-account";
      button.textContent = "Continue as " + account.given_name;
      button.addEventListener("click", async () => {
        buttons.forEach(choice => { choice.disabled = true; });
        status.textContent = "";
        const body = new URLSearchParams({
          client_id: options.client_id, account_id: account.id,
          disclosure_text_shown: "false", is_auto_selected: "false"
        });
        if (options.nonce) body.set("nonce", options.nonce);
        try {
          const response = await fetch(idp + "/gsi/fallback/issue", { ...fallbackOptions, method: "POST", body, signal });
          if (!response.ok) throw new Error();
          const { token } = await response.json();
          if (!signal.aborted) deliver(options, token, "btn");
        } catch {
          if (signal.aborted) return;
          status.textContent = "Keystone ID could not sign you in. Try again.";
          buttons.forEach(choice => { choice.disabled = false; });
        }
      });
      return button;
    });
    if (buttons.length) {
      panel.append(...buttons, status);
    } else {
      const link = document.createElement("a");
      link.href = idp + "/signin";
      link.textContent = "Sign in to Keystone ID";
      panel.append(link);
    }
    document.body.append(panel);
  }

  async function prompt(notification) {
    if (!configuration?.client_id || suppressed()) {
      notification?.({ isNotDisplayed: () => true });
      return;
    }

    cancel();
    request = new AbortController();
    const { signal } = request;
    const options = configuration;
    if (typeof IdentityCredential !== "undefined" && navigator.credentials?.get) {
      try {
        const provider = { configURL, clientId: options.client_id };
        if (options.nonce) provider.nonce = options.nonce;
        const identity = { context: "signin", providers: [provider] };
        const credential = await navigator.credentials.get({ identity, mediation: "optional", signal });
        if (credential?.token && !signal.aborted) {
          deliver(options, credential.token, "fedcm");
          return;
        }
      } catch {
        if (signal.aborted) return;
      }
    }

    if (!signal.aborted) await fallback(options, signal);
  }

  function renderButton(parent, options = {}) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "one-tap-account";
    button.textContent = options.text === "signup_with" ? "Sign up with Keystone ID" : "Continue with Keystone ID";
    button.addEventListener("click", () => {
      options.click_listener?.();
      void prompt();
    });
    parent.append(button);
  }

  const google = window.google ||= {};
  const accounts = google.accounts ||= {};
  accounts.id = { initialize, prompt, renderButton, disableAutoSelect, cancel };

  const onload = document.getElementById("g_id_onload");
  if (onload) {
    const { client_id, ux_mode, callback, auto_select, itp_support, nonce, auto_prompt } = onload.dataset;
    initialize({ client_id, ux_mode, callback, auto_select: auto_select === "true", itp_support: itp_support === "true", nonce });
    if (auto_prompt !== "false") void prompt();
  }
})();
