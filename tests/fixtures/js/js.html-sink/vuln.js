// dynamic HTML written to the DOM; lines that must be reported are marked
window.addEventListener("message", (event) => {
  if (event.origin !== "https://example.com") return;
  document.getElementById("out").innerHTML = event.data.html; // VULN
  banner.outerHTML = `<div>${event.data.title}</div>`; // VULN
  list.innerHTML += "<li>" + event.data.item + "</li>"; // VULN
  document.write(event.data.page); // VULN
  panel.insertAdjacentHTML("beforeend", event.data.html); // VULN
});
