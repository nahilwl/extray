const TRUSTED = "https://app.example.com";

chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
  if (sender.origin !== TRUSTED) return;
  chrome.cookies.getAll({ domain: "example.com" }, sendResponse);
  return true;
});

chrome.runtime.onMessageExternal.addListener(function (msg, { id }) {
  if (id === "abcdefghijklmnopabcdefghijklmnop") localStorage.setItem("token", msg.token);
});

function handleExternal(msg, sender, reply) {
  if (new URL(sender.url).host === "app.example.com") reply(lookup(msg.key));
}
browser.runtime.onMessageExternal.addListener(handleExternal);

chrome.runtime.onMessage.addListener((msg, sender) => run(msg)); // internal messages: other rules
chrome.runtime.onMessageExternal.addListener(router.dispatch.bind(router)); // INFO: not resolvable, reported as not analyzed
