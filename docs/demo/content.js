const panel = document.createElement("aside");
panel.className = "price-watch";
document.body.append(panel);

// the shop page hands over its product data through postMessage
window.addEventListener("message", (event) => {
  const { product, price } = event.data;
  panel.innerHTML = `<h2>${product}</h2><p class="price">${price}</p>`;
});

const coupon = new URLSearchParams(location.search).get("coupon");
if (coupon) {
  panel.insertAdjacentHTML("beforeend", `<p>Coupon applied: ${coupon}</p>`);
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "history") {
    panel.querySelector(".price").title = msg.summary;
  }
});
