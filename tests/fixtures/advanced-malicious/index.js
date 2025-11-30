const fs = require("fs");
const vm = require("vm");

// FS Analyzer trigger
fs.readFileSync("/etc/passwd");

// Dynamic Analyzer trigger
const code = 'console.log("evil")';
vm.runInNewContext(code);

// Dynamic require
require("path" + "/to/evil");
