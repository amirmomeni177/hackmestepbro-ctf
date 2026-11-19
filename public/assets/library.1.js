const search = document.getElementById("challenge-query");
const count = document.getElementById("challenge-count");
const cards = [...document.querySelectorAll("[data-challenge]")];

for (const card of cards) {
  try {
    if (localStorage.getItem("ctf:solved:" + card.dataset.challenge) === "1") {
      const status = card.querySelector(".challenge-action");
      status.textContent = "Solved · Play again";
      status.setAttribute("data-solved", "");
    }
  } catch {
    // Challenge links work when storage is unavailable.
  }
}

document.getElementById("library-search").hidden = false;
search.addEventListener("input", () => {
  const query = search.value.trim().toLowerCase();
  let visible = 0;
  for (const card of cards) {
    card.hidden = !card.dataset.search.includes(query);
    if (!card.hidden) visible += 1;
  }
  count.textContent = visible === 1 ? "1 challenge" : visible + " challenges";
  document.getElementById("no-challenges").hidden = visible > 0;
});
