window.addEventListener("message", (event) => {
  if (event.origin !== "https://example.com") return;
  document.getElementById("out").textContent = event.data.html;
  banner.replaceChildren(Object.assign(document.createElement("div"), { textContent: event.data.title }));
  list.innerHTML = ""; // constant markup is safe
  list.append(Object.assign(document.createElement("li"), { textContent: event.data.item }));
  panel.insertAdjacentHTML("beforeend", "<hr>");
  panel.insertAdjacentText("beforeend", event.data.html);
});
