chrome.runtime.onMessage.addListener((msg) => {
  const data = JSON.parse(msg.code);
  const getGlobal = Function("return this"); // constant code, common in bundles
  setTimeout(() => update(msg.id), 100);
  setInterval(poll, 1000, msg.id);
  setTimeout(callback, 0); // identifier: a function, not a string
  run(data, getGlobal);
});
