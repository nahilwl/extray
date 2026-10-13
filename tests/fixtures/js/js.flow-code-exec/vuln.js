// attacker-controlled data reaching code execution; lines that must be reported are marked
window.addEventListener("message", (event) => {
  const { code } = event.data;
  eval(code); // VULN
  setTimeout("tick(" + event.data.n + ")", 10); // VULN
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "inject") {
    chrome.scripting.executeScript({ target: { tabId: sender.tab.id }, code: msg.payload }); // VULN
  }
});

chrome.runtime.onMessageExternal.addListener((req) => {
  const fn = new Function("x", req.body); // VULN
  fn(1);
});

const hash = decodeURIComponent(location.hash.slice(1));
eval(hash); // VULN
