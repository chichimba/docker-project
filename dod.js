const { exec } = require("child_process");
function run(cmd) { exec(cmd, (e,o)=>console.log(o)); } // VULN
function xss(q) { return eval(q); }                     // VULN
module.exports = { run, xss };