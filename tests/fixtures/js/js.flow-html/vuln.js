// attacker-controlled data written as HTML; lines that must be reported are marked
window.addEventListener("message", ({ data }) => {
  const card = document.createElement("div");
  card.innerHTML = `<h1>${data.title}</h1>`; // VULN
  list.innerHTML += "<li>" + data.item + "</li>"; // VULN
});

const params = new URLSearchParams(location.search);
const q = params.get("q");
results.insertAdjacentHTML("beforeend", "<p>Results for " + q + "</p>"); // VULN

document.write(document.referrer); // VULN

chrome.runtime.onMessage.addListener((msg) => {
  fetch(msg.url).then((r) => r.text()).then(() => {
    panel.outerHTML = msg.html; // VULN
  });
});
