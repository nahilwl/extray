window.addEventListener("message", ({ data, origin }) => {
  if (origin !== "https://example.com") return;
  const card = document.createElement("div");
  card.innerHTML = `<h1>${data.title}</h1>`;
});

const params = new URLSearchParams(location.search);
const q = params.get("q");
results.append(Object.assign(document.createElement("p"), { textContent: "Results for " + q }));
results.insertAdjacentHTML("beforeend", DOMPurify.sanitize(q));

document.querySelector("#ref").textContent = document.referrer;

chrome.runtime.onMessage.addListener((msg) => {
  panel.textContent = msg.html;
  panel.innerHTML = "<p>loading</p>";
});
