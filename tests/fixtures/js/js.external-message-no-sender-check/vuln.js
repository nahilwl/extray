// external message listeners that trust every sender; lines that must be reported are marked
chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => { // VULN
  chrome.cookies.getAll({}, sendResponse);
  return true;
});

chrome.runtime.onMessageExternal.addListener(function (msg) { // VULN
  localStorage.setItem("token", msg.token);
});

function handleExternal(msg, sender, reply) {
  if (sender.tab) reply(lookup(msg.key));
}
browser.runtime.onMessageExternal.addListener(handleExternal); // VULN
