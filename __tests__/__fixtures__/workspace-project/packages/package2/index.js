const { exec } = require('child_process');
exec('rm -rf /tmp/*');
const fs = require('fs');
fs.readFileSync('/etc/passwd');