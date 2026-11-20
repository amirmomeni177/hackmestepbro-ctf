(() => {
  const script = document.currentScript;
  const base = new URL("../", script.src).pathname.replace(/\/$/, "");
  let manifest;

  function csrfToken() {
    const cookie = document.cookie.split("; ").find(entry => entry.startsWith("csrftoken="));
    return cookie ? decodeURIComponent(cookie.slice("csrftoken=".length)) : "";
  }

  async function graphql(operationName, variables) {
    manifest ||= fetch(base + "/persisted.json", { credentials: "include" })
      .then(response => {
        if (!response.ok) throw new Error("Lumora could not load the operation. Try again.");
        return response.json();
      })
      .catch(error => {
        manifest = undefined;
        throw error;
      });
    const operationId = (await manifest)[operationName];
    const response = await fetch(base + "/graphql", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
      body: JSON.stringify({ operationName, variables, extensions: { operationId } })
    });
    const result = await response.json();
    if (result.errors?.length) throw new Error(result.errors.map(error => error.message).join(" "));
    if (!response.ok) throw new Error("Lumora could not complete the request. Try again.");
    return result.data;
  }

  window.lumoraGraphQL = graphql;

  const settings = document.getElementById("one-tap-settings");
  if (!settings) return;

  const banner = document.getElementById("tracking-consent");
  const errorMessage = document.getElementById("one-tap-error");
  window.handleOneTapCredential = async ({ credential }) => {
    errorMessage.hidden = true;
    try {
      const { signInWithOauth } = await graphql("SignInWithOAuthMutation", {
        input: { idToken: credential, provider: "GOOGLE_OAUTH2", platform: "WEB" }
      });
      if (signInWithOauth.errors.length) {
        throw new Error(signInWithOauth.errors.map(error => error.message).join(" "));
      }
      if (location.pathname === base + "/") location.reload();
      else location.assign(base + "/");
    } catch (error) {
      errorMessage.textContent = error.message;
      errorMessage.hidden = false;
    }
  };

  function startOneTap() {
    banner.hidden = true;
    settings.replaceWith(settings.content);
    const client = document.createElement("script");
    client.nonce = script.nonce;
    client.src = base + "/idp/gsi/client";
    document.head.append(client);
  }

  try {
    if (localStorage.getItem("trackingConsent") === "true") {
      startOneTap();
    } else {
      banner.hidden = false;
      banner.querySelector("button").addEventListener("click", () => {
        try {
          localStorage.setItem("trackingConsent", "true");
          startOneTap();
        } catch {
          errorMessage.textContent = "Lumora could not save your cookie preference.";
          errorMessage.hidden = false;
        }
      });
    }
  } catch {
    // Keep One Tap off when browser storage cannot be read.
  }
})();
