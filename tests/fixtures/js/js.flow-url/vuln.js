// attacker-controlled URLs opened or fetched; lines that must be reported are marked
chrome.runtime.onMessageExternal.addListener((request) => {
  chrome.tabs.create({ url: request.url }); // VULN
  const opts = { url: request.next, active: true };
  chrome.tabs.update(request.tabId, opts); // VULN
});

window.addEventListener("message", (e) => {
  fetch(`https://api.example.com/${e.data.path}`); // VULN
  location.assign(e.data.redirect); // VULN
  window.location.replace(e.data.redirect); // VULN
  window.open(e.data.popup); // VULN
});

location.href = new URLSearchParams(location.search).get("next"); // VULN
