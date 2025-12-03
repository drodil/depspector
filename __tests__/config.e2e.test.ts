import { describe, it, expect } from "vitest";
import { join } from "path";
import { invokeCli, getFixturePath } from "./helpers";

const configsDir = join(__dirname, "configs");

describe("Config E2E", () => {
  it("should override analyzer severity via config", () => {
    const configPath = join(configsDir, "process-low.json");
    const { stdout, stderr, exitCode } = invokeCli([
      "--cwd",
      getFixturePath("simple-package"),
      "--offline",
      "--cache",
      "false",
      "--config",
      configPath,
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/\bprocess\b/i);
    expect(output).toMatch(/LOW \[process\]/i);
    expect(output).not.toMatch(/CRITICAL \[process\]/i);
    expect(exitCode).toBe(0);
  });

  it("should disable secrets analyzer via config", () => {
    const configPath = join(configsDir, "disable-secrets.json");
    const { stdout, stderr, exitCode } = invokeCli([
      "--cwd",
      getFixturePath("secrets-package"),
      "--offline",
      "--cache",
      "false",
      "--config",
      configPath,
    ]);

    const output = stdout + stderr;
    expect(output).not.toMatch(/\bsecrets\b/i);
    expect(output).toContain("No issues found");
    expect(exitCode).toBe(0);
  });

  it("should respect exitWithFailureOnLevel off", () => {
    const configPath = join(configsDir, "exit-off.json");
    const { stdout, stderr, exitCode } = invokeCli([
      "--cwd",
      getFixturePath("multi-issue-package"),
      "--offline",
      "--cache",
      "false",
      "--config",
      configPath,
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/Found \d+ issues/i);
    expect(exitCode).toBe(0);
  });
});
