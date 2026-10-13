window.addEventListener("message", (event) => {
  if (event.origin !== "https://example.com") return;
  const { code } = event.data;
  run(JSON.stringify(code));
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "inject") {
    chrome.scripting.executeScript({ target: { tabId: sender.tab.id }, files: ["inject.js"] });
  }
});

chrome.runtime.onMessageExternal.addListener((req, sender) => {
  if (sender.id !== "abcdefghijklmnopabcdefghijklmnop") return;
  const handlers = { reload: () => location.reload() };
  handlers[req.action]?.();
});

const hash = decodeURIComponent(location.hash.slice(1));
setTimeout(() => show(hash), 10);
eval("1 + 1");
