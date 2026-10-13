window.addEventListener("message", function (event) {
  if (event.origin !== "https://example.com") return;
  document.body.textContent = event.data;
});

const ALLOWED = ["https://a.example"];
const onMessage = (e) => {
  if (!ALLOWED.includes(e.origin)) return;
  run(e.data);
};
window.addEventListener("message", onMessage);

window.addEventListener("message", ({ data, origin }) => {
  if (origin === "https://example.com") save(data);
});

window.addEventListener("message", (event) => {
  const { origin: from, data } = event;
  if (from === "https://example.com") save(data);
});

window.addEventListener("click", (e) => go(e.target)); // not a message listener
window.addEventListener("message", this.handler.bind(this)); // not resolvable, not reported
