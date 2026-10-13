// dynamic HTML written to the DOM from trusted data: info findings, lines marked
window.addEventListener("message", (event) => {
  if (event.origin !== "https://example.com") return;
  document.getElementById("out").innerHTML = event.data.html; // INFO
  banner.outerHTML = `<div>${event.data.title}</div>`; // INFO
  list.innerHTML += "<li>" + event.data.item + "</li>"; // INFO
  document.write(event.data.page); // INFO
  panel.insertAdjacentHTML("beforeend", event.data.html); // INFO
});
