// code built from strings at runtime; lines that must be reported are marked
chrome.runtime.onMessage.addListener((msg) => {
  eval(msg.code); // VULN
  const fn = new Function("a", msg.body); // VULN
  window.eval(`run(${msg.arg})`); // VULN
  setTimeout("update('" + msg.id + "')", 100); // VULN
  setInterval(`poll(${msg.id})`, 1000); // VULN
  Function(msg.body)(); // VULN
});
