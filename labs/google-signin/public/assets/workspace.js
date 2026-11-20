(() => {
  const workspace = document.querySelector("[data-workspace-page]");
  if (!workspace) return;

  const graphql = window.lumoraGraphQL;
  const dates = new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeZone: "UTC" });
  const graphemes = typeof Intl.Segmenter === "function" ? new Intl.Segmenter() : null;

  function nameParts(name) {
    return name.split(/\p{White_Space}+/u).filter(Boolean);
  }

  function initials(name) {
    return nameParts(name).slice(0, 2).map(word => {
      if (!graphemes) return Array.from(word)[0];
      const [first] = graphemes.segment(word);
      return first.segment;
    }).join("").toUpperCase();
  }

  function renderProfile(profile) {
    const fields = {
      "[data-profile-name]": profile.name,
      "[data-profile-email]": profile.email,
      "[data-profile-initials]": initials(profile.name),
      "[data-profile-provider]": profile.signInProvider === "keystone_id" ? "Keystone ID" : profile.signInProvider
    };
    Object.entries(fields).forEach(([selector, value]) => {
      workspace.querySelectorAll(selector).forEach(element => { element.textContent = value; });
    });
  }

  function renderDate(element, value) {
    element.dateTime = value;
    element.textContent = dates.format(new Date(value));
  }

  async function loadDashboard() {
    const { currentUser } = await graphql("DashboardQuery");
    if (!currentUser) return;

    renderProfile(currentUser);
    const [firstName] = nameParts(currentUser.name);
    workspace.querySelector("[data-dashboard-greeting]").textContent = firstName ? `Welcome back, ${firstName}.` : "Welcome back.";
    workspace.querySelector("[data-workspace-name]").textContent = currentUser.workspace.name;

    const cards = workspace.querySelectorAll(".recent-board");
    currentUser.boards.forEach((board, index) => {
      const card = cards[index];
      card.querySelector("h3").textContent = board.title;
      card.querySelector("[data-assets-count]").textContent = board.assetsCount;
      card.querySelector(".board-art").style.setProperty("--cover-hue", `${board.coverHue}deg`);
      renderDate(card.querySelector("time"), board.updatedAt);
    });

    const rows = workspace.querySelectorAll(".activity li");
    currentUser.activity.forEach((item, index) => {
      const row = rows[index];
      row.querySelector(".avatar").textContent = initials(item.actorName);
      row.querySelector("[data-actor]").textContent = item.actorName;
      row.querySelector("[data-verb]").textContent = item.verb;
      row.querySelector("[data-board-title]").textContent = item.boardTitle;
      renderDate(row.querySelector("time"), item.at);
    });
  }

  async function loadAccount() {
    const form = workspace.querySelector(".display-name-form");
    const fieldset = form.querySelector("fieldset");
    const input = form.elements.namedItem("name");
    const status = form.querySelector("[role=status]");
    form.querySelector("#display-name-note").hidden = true;

    form.addEventListener("submit", async event => {
      event.preventDefault();
      const name = input.value;
      input.removeAttribute("aria-invalid");
      fieldset.disabled = true;
      status.textContent = "Saving…";
      status.classList.remove("is-error");

      try {
        const { updateProfile } = await graphql("UpdateProfile", { input: { name } });

        if (updateProfile.errors.length) {
          input.setAttribute("aria-invalid", "true");
          throw new Error(updateProfile.errors.map(error => error.message).join(" "));
        }
        renderProfile(updateProfile.currentUser);
        input.value = updateProfile.currentUser.name;
        status.textContent = "Display name saved.";
      } catch (error) {
        status.classList.add("is-error");
        status.textContent = error.message;
      } finally {
        fieldset.disabled = false;
      }
    });

    try {
      const { currentUser } = await graphql("AccountQuery");
      if (currentUser) {
        renderProfile(currentUser);
        input.value = currentUser.name;
      }
    } catch {
      // Keep the server-rendered profile if the refresh fails.
    } finally {
      fieldset.disabled = false;
    }
  }

  if (workspace.dataset.workspacePage === "account") {
    loadAccount();
  } else {
    loadDashboard().catch(() => { /* Keep the server-rendered dashboard. */ });
  }
})();
