const get = (id) => document.getElementById(id);
const form = get("finding");
const verifyButton = form.querySelector("button[type=submit]");
const verdict = get("verdict");
const flagResult = get("flag-result");
const copyButton = get("copy");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (verifyButton.disabled) return;
  verifyButton.disabled = true;
  verdict.textContent = "Checking…";
  flagResult.hidden = true;
  try {
    const answer = Object.fromEntries(new FormData(form));
    const reply = await fetch("/api/verify", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(answer),
    });
    if (!reply.ok) throw new Error("Verification unavailable");
    const response = await reply.json();
    if (!response.solved) {
      verdict.textContent = response.message;
      return;
    }
    try {
      localStorage.setItem("ctf:solved:the-wrong-window", "1");
    } catch {
      // The flag is available even when saving progress is disabled.
    }
    get("flag").textContent = response.flag;
    copyButton.textContent = "Copy flag";
    verdict.textContent = "Correct. Your flag is ready.";
    flagResult.hidden = false;
  } catch {
    verdict.textContent = "Verification is unavailable. Try again.";
  } finally {
    verifyButton.disabled = false;
  }
});

copyButton.addEventListener("click", async () => {
  const flag = get("flag");
  try {
    await navigator.clipboard.writeText(flag.textContent);
    copyButton.textContent = "Copied";
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(flag);
    selection.removeAllRanges();
    selection.addRange(range);
    copyButton.textContent = "Flag selected";
  }
});

verifyButton.disabled = false;
