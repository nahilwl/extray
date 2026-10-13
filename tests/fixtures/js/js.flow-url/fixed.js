const ROUTES = { home: "https://example.com/", help: "https://example.com/help" };

chrome.runtime.onMessageExternal.addListener((request, sender) => {
  if (sender.origin !== "https://example.com") return;
  chrome.tabs.create({ url: request.url });
});

window.addEventListener("message", (e) => {
  fetch("https://api.example.com/status");
  location.assign(ROUTES[e.data.page]);
  window.open(chrome.runtime.getURL("popup.html"));
  chrome.tabs.create({ url: "https://example.com/welcome" });
});

location.href = ROUTES[new URLSearchParams(location.search).get("next")];
