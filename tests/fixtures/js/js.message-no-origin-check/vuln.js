// postMessage listeners that accept data from any origin; lines that must be reported are marked
window.addEventListener("message", function (event) { // VULN
  document.body.textContent = event.data;
});

window.addEventListener('message', (e) => { // VULN
  if (location.origin === "https://example.com") chrome.runtime.sendMessage(e.data);
});

function onMessage(event) {
  run(event.data);
}
self.addEventListener("message", onMessage); // VULN

addEventListener("message", ({ data }) => save(data)); // VULN

window.addEventListener("message", () => refresh()); // VULN
