// code built from strings whose origin is unknown (no tracked source); lines that must be reported are marked
function applyConfig(config) {
  eval(config.code); // VULN
  const fn = new Function("a", config.body); // VULN
  window.eval(`run(${config.arg})`); // VULN
  setTimeout("update('" + config.id + "')", 100); // VULN
  setInterval(`poll(${config.id})`, 1000); // VULN
  Function(config.body)(); // VULN
}
