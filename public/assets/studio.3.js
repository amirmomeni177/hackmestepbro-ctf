const get = (id) => document.getElementById(id);
const content = get("studio-content");
const views = {
  "/studio": {title: "Overview", detail: "Here's what's happening across your creator studio.", data: "/api/studio/summary", render: showOverview},
  "/studio/media": {title: "Media library", detail: "Browse the posts and drafts synced to your studio.", data: "/api/media/items", render: showMedia, history: "/api/media/delivery"},
  "/studio/analytics": {title: "Activity", detail: "See how your content is performing and review recent audience events.", data: "/api/analytics/overview", render: showActivity, history: "/api/analytics/diagnostics"},
  "/studio/settings/connection": {title: "Connections", detail: "Manage the creator account connected to Afterframe.", data: "/api/settings/account", render: showConnection, history: "/api/settings/delivery"},
  "/studio/help": {title: "Help center", detail: "Find answers about your creator studio.", data: "/api/support/articles", render: showHelp, history: "/api/support/delivery"},
};

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function link(label, path) {
  const node = el("a", label, "text-link");
  node.href = path;
  return node;
}

async function read(path) {
  const response = await fetch(path);
  if (response.status === 401) {
    window.location.assign("/challenges/the-wrong-window");
    throw new Error("Demo session ended");
  }
  if (!response.ok) throw new Error("Studio data unavailable");
  return response.json();
}

function panel(title) {
  const box = el("section", "", "panel studio-panel");
  const heading = el("div", "", "panel-top");
  heading.append(el("h2", title));
  box.append(heading);
  return box;
}

function stats(entries) {
  const grid = el("dl", "", "metric-grid");
  for (const [label, amount] of entries) {
    const item = el("div", "", "panel metric");
    item.append(el("dt", label), el("dd", new Intl.NumberFormat("en").format(amount)));
    grid.append(item);
  }
  return grid;
}

function selector(label, values, onChange) {
  const container = el("label", "", "studio-filter");
  const select = el("select");
  for (const value of values) select.append(el("option", value));
  select.addEventListener("change", () => onChange(select.value));
  container.append(el("span", label), select);
  return container;
}

function mediaCards(entries) {
  const grid = el("div", "", "media-grid");
  for (const item of entries) {
    const card = el("article", "", "panel media-card");
    const imageClass = ["violet", "rose", "blue", "green"].includes(item.tone) ? item.tone : "violet";
    const image = el("div", "", "media-art " + imageClass);
    image.setAttribute("aria-hidden", "true");
    const caption = el("div", "", "media-caption");
    caption.append(el("h3", item.name), el("p", item.kind + " · " + item.date, "muted"));
    card.append(image, caption, el("span", item.status, "tag media-tag"));
    grid.append(card);
  }
  return grid;
}

function showOverview(data) {
  content.append(stats([["Posts", data.posts], ["Audience reach", data.reach], ["Queued events", data.review]]));
  const heading = el("div", "", "studio-row-heading");
  heading.append(el("h2", "Recent media"), link("Open media library", "/studio/media"));
  content.append(heading, mediaCards(data.media));
}

function showMedia(data) {
  const results = el("div");
  function update(filter) {
    const items = data.items.filter(item => filter === "All" || item.status === filter);
    results.replaceChildren(mediaCards(items));
  }
  content.append(selector("Status", ["All", "Published", "Draft"], update), results);
  update("All");
}

function showActivity(data) {
  content.append(stats([["Accounts reached", data.reach], ["Views", data.views], ["Saves", data.saves]]));
  const box = panel("Recent events");
  const list = el("ul", "", "studio-list");
  function draw(status) {
    const filtered = data.events.filter(item => status === "All" || item.status === status);
    list.replaceChildren();
    for (const item of filtered) {
      const row = el("li");
      const name = el("div");
      name.append(el("strong", item.name), el("small", item.time + " · " + item.source));
      row.append(name, el("span", item.status, item.status === "Reviewed" ? "tag good" : "tag media-tag"));
      list.append(row);
    }
  }
  box.querySelector(".panel-top").append(selector("Status", ["All", "Reviewed", "Queued"], draw));
  box.append(list);
  content.append(box);
  draw("All");
}

function showConnection(data) {
  const box = panel("Connected accounts");
  const row = el("div", "", "connected-row");
  const user = el("div", "", "workspace-account");
  const profile = el("span");
  profile.append(el("strong", data.displayName), el("small", data.handle + " · " + data.provider));
  user.append(el("span", "RL", "avatar"), profile);
  row.append(user, el("span", data.status, "tag good"));
  box.append(row);
  content.append(box);
}

function showHelp(data) {
  const box = panel("Studio guides");
  const list = el("div", "", "help-articles");
  for (const article of data.articles) {
    const details = el("details");
    details.append(el("summary", article.title), el("p", article.body, "muted"));
    list.append(details);
  }
  box.append(list);
  content.append(box);
}

function deliveryHistory(path) {
  const box = panel("Integration");
  const body = el("div", "", "history-body");
  const button = el("button", "View delivery history", "button secondary");
  const entries = el("div", "", "delivery-list");
  button.type = "button";
  button.setAttribute("aria-expanded", "false");
  entries.hidden = true;
  entries.id = "delivery-list";
  entries.setAttribute("role", "status");
  button.setAttribute("aria-controls", entries.id);
  button.addEventListener("click", async () => {
    if (!entries.hidden) {
      entries.hidden = true;
      button.textContent = "View delivery history";
      button.setAttribute("aria-expanded", "false");
      return;
    }
    button.disabled = true;
    entries.hidden = false;
    entries.textContent = "Loading history…";
    button.setAttribute("aria-expanded", "true");
    try {
      const history = await read(path);
      const list = el("ul", "", "studio-list");
      for (const delivery of history.deliveries) {
        const row = el("li");
        const name = el("div");
        const time = new Date(delivery.time).toLocaleTimeString("en", {hour: "2-digit", minute: "2-digit", timeZone: "UTC", hour12: false});
        name.append(el("strong", delivery.event), el("small", time + " UTC · " + delivery.effect));
        row.append(name, el("span", delivery.disposition, delivery.disposition === "Applied" ? "tag good" : "tag media-tag"));
        list.append(row);
      }
      entries.replaceChildren(list);
      button.textContent = "Hide delivery history";
    } catch {
      entries.textContent = "Delivery history is unavailable. Close and reopen it to retry.";
      button.textContent = "Hide delivery history";
    } finally {
      button.disabled = false;
    }
  });
  body.append(button, entries);
  box.append(body);
  return box;
}

async function loadView() {
  const path = window.location.pathname;
  const view = views[path];
  const active = [...document.querySelectorAll(".studio-nav a")].find(item => item.getAttribute("href") === path);
  active?.setAttribute("aria-current", "page");
  get("breadcrumb").textContent = view.title;
  document.title = view.title + " — Afterframe";
  const intro = el("div", "", "page-intro");
  intro.append(el("h1", view.title), el("p", view.detail, "muted"));
  content.replaceChildren(intro);
  try {
    const data = await read(view.data);
    view.render(data);
    if (view.history) content.append(deliveryHistory(view.history));
  } catch {
    content.append(el("p", "This page is unavailable. Refresh to try again.", "notice"));
  }
}

const signOut = get("sign-out");
signOut.addEventListener("click", async () => {
  signOut.disabled = true;
  try {
    const response = await fetch("/api/demo/signout", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: "{}",
    });
    if (!response.ok) throw new Error("Sign-out unavailable");
    window.location.assign("/challenges/the-wrong-window");
  } catch {
    signOut.textContent = "Retry sign out";
    signOut.disabled = false;
  }
});

loadView();
