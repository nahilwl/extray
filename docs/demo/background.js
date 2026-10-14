chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => {
  if (msg.type === "open-deal") {
    chrome.tabs.create({ url: msg.url });
  }
  reply({ ok: true });
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "track") {
    chrome.storage.local.set({ [msg.product]: msg.price });
  }
});
