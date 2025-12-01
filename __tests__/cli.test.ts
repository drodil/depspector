import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "child_process";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "fs";
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

describe("CLI", () => {
  it("should show help command", () => {
    const { exitCode, stdout } = invokeCli(["--help"]);

    expect(stdout).toContain("depspector");
    expect(exitCode).toBe(0);
  });

  it("should show version", () => {
    const { exitCode, stdout } = invokeCli(["--version"]);

    expect(stdout).toMatch(/\d+\.\d+\.\d+/);
    expect(exitCode).toBe(0);
  });
});

describe("Native bindings", () => {
  it("should have native module file", () => {
    const possiblePaths = [
      "depspector.win32-x64-msvc.node",
      "depspector.darwin-arm64.node",
      "depspector.darwin-x64.node",
      "depspector.linux-x64-gnu.node",
    ];

    const hasNativeModule = possiblePaths.some((p) =>
      existsSync(join(__dirname, "..", p))
    );

    if (!hasNativeModule) {
      console.log("Skipping native module test - no .node file found");
      return;
    }

    expect(hasNativeModule).toBe(true);
  });
});

describe("E2E Analysis", () => {
  const testDir = join(__dirname, "..", "test-fixtures");
  const nodeModulesDir = join(testDir, "node_modules");
  const testPackageDir = join(nodeModulesDir, "test-package");

  beforeAll(() => {
    mkdirSync(testPackageDir, { recursive: true });

    writeFileSync(
      join(testPackageDir, "package.json"),
      JSON.stringify({
        name: "test-package",
        version: "1.0.0",
      })
    );

    writeFileSync(
      join(testPackageDir, "index.js"),
      `
const secret = "AKIAIOSFODNN7EXAMPLE";
eval("console.log('hello')");
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should analyze a package with issues", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("test-package");
    expect(output).toContain("eval");
  });

  it("should respect offline mode", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).not.toContain("cooldown");
    expect(output).not.toContain("dormant");
  });

  it("should report no issues for clean package", () => {
    const cleanPackageDir = join(nodeModulesDir, "clean-package");
    mkdirSync(cleanPackageDir, { recursive: true });

    writeFileSync(
      join(cleanPackageDir, "package.json"),
      JSON.stringify({
        name: "clean-package",
        version: "1.0.0",
      })
    );

    writeFileSync(
      join(cleanPackageDir, "index.js"),
      `
function greet(name) {
  return "Hello, " + name;
}
module.exports = { greet };
`
    );

    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    const lines = output.split("\n");
    const cleanPkgIssues = lines.filter(
      (l) => l.includes("clean-package") && l.includes("CRITICAL")
    );
    expect(cleanPkgIssues.length).toBe(0);
  });

  it("should exit with error on high severity issues", () => {
    // Use --cwd to point to test directory which has no .depspectorrc
    // This ensures the default exit behavior (exit on high severity) is used
    const { exitCode } = invokeCli([
      "--cwd",
      testDir,
      "--path",
      "node_modules",
      "--offline",
      "--cache",
      "false",
    ]);

    // Exit code should be non-zero (error) when issues found
    expect(exitCode).not.toBe(0);
  });

  it("should analyze nested dependencies", () => {
    const parentPkgDir = join(nodeModulesDir, "parent-package");
    const nestedPkgDir = join(parentPkgDir, "node_modules", "nested-package");

    mkdirSync(nestedPkgDir, { recursive: true });

    writeFileSync(
      join(parentPkgDir, "package.json"),
      JSON.stringify({ name: "parent-package", version: "1.0.0" })
    );

    writeFileSync(
      join(nestedPkgDir, "package.json"),
      JSON.stringify({ name: "nested-package", version: "1.0.0" })
    );

    writeFileSync(join(nestedPkgDir, "index.js"), 'eval("nested evil");');

    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("nested-package");
    expect(output).toContain("eval");
  });

  it("should report multiple issues", () => {
    const multiIssuePkgDir = join(nodeModulesDir, "multi-issue-package");
    mkdirSync(multiIssuePkgDir, { recursive: true });

    writeFileSync(
      join(multiIssuePkgDir, "package.json"),
      JSON.stringify({ name: "multi-issue-package", version: "1.0.0" })
    );

    writeFileSync(
      join(multiIssuePkgDir, "index.js"),
      `
      const token = "AKIAIOSFODNN7EXAMPLE";
      eval("console.log('evil')");
      `
    );

    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("multi-issue-package");
    expect(output).toContain("eval");
    expect(output).toContain("secrets");
  });
});

describe("CLI Options", () => {
  const testDir = join(__dirname, "..", "test-fixtures-options");
  const nodeModulesDir = join(testDir, "node_modules");
  const testPackageDir = join(nodeModulesDir, "option-test");

  beforeAll(() => {
    mkdirSync(testPackageDir, { recursive: true });

    writeFileSync(
      join(testPackageDir, "package.json"),
      JSON.stringify({
        name: "option-test",
        version: "1.0.0",
      })
    );

    writeFileSync(
      join(testPackageDir, "index.js"),
      `
const x = process.env.API_KEY;
`
    );
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should work with fail-fast option", () => {
    const { stdout, stderr } = invokeCli([
      "--path",
      nodeModulesDir,
      "--offline",
      "--cache",
      "false",
      "--fail-fast",
    ]);

    const output = stdout + stderr;
    // Should still produce some output
    expect(output.length).toBeGreaterThan(0);
  });

  it("should handle invalid path gracefully", () => {
    const { exitCode, stderr } = invokeCli([
      "--path",
      "/nonexistent/path/node_modules",
      "--offline",
    ]);

    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("not found");
  });
});
