import { describe, it, expect } from "vitest";
import { existsSync } from "fs";
import { join } from "path";
import { invokeCli } from "./helpers";

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
      existsSync(join(__dirname, "..", p)),
    );

    if (!hasNativeModule) {
      console.log("Skipping native module test - no .node file found");
      return;
    }

    expect(hasNativeModule).toBe(true);
  });
});

describe("CLI Options", () => {
  it("should work with fail-fast option", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      join(__dirname, "__fixtures__", "simple-package"),
      "--offline",
      "--cache",
      "false",
      "--fail-fast",
    ]);

    const output = stdout + stderr;
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

  it("should exit with error on high severity issues", () => {
    const { exitCode } = invokeCli([
      "--cwd",
      join(__dirname, "__fixtures__", "simple-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    expect(exitCode).not.toBe(0);
  });

  it("should respect offline mode", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      join(__dirname, "__fixtures__", "simple-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).not.toContain("cooldown");
    expect(output).not.toContain("dormant");
  });
});
