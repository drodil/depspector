import { describe, it, expect } from "vitest";
import { invokeCli, getFixturePath } from "./helpers";

describe("Buffer Analyzer", () => {
  it("should detect Buffer usage", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("buffer-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("buffer-test");
    expect(output).toMatch(/buffer/i);
  });
});

describe("Dynamic Analyzer", () => {
  it("should detect dynamic Function constructor", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("dynamic-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("dynamic-test");
    expect(output).toMatch(/function/i);
  });
});

describe("Env Analyzer", () => {
  it("should detect environment variable access", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("env-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("env-test");
    expect(output).toMatch(/env/i);
  });
});

describe("Eval Analyzer", () => {
  it("should detect eval usage", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("eval-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("eval-test");
    expect(output).toMatch(/eval/i);
  });
});

describe("FileSystem Analyzer", () => {
  it("should detect filesystem operations", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("fs-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("fs-test");
    expect(output).toMatch(/fs|file/i);
  });
});

describe("Metadata Analyzer", () => {
  it("should detect metadata issues", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("metadata-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("metadata-test");
    expect(output).toMatch(/metadata|missing/i);
  });
});

describe("Minified Analyzer", () => {
  it("should detect minified code", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("minified-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("minified-test");
    expect(output).toMatch(/minified/i);
  });
});

describe("Network Analyzer", () => {
  it("should detect network requests", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("network-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("network-test");
    expect(output).toMatch(/network|http/i);
  });
});

describe("Obfuscation Analyzer", () => {
  it("should detect obfuscated code", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("obfuscation-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("obfuscation-test");
    expect(output).toMatch(/obfuscat/i);
  });
});

describe("Pollution Analyzer", () => {
  it("should detect prototype pollution", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("pollution-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("pollution-test");
    expect(output).toMatch(/pollution|proto/i);
  });
});

describe("Process Analyzer", () => {
  it("should detect process execution", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("process-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("process-test");
    expect(output).toMatch(/process|exec|spawn/i);
  });
});

describe("Secrets Analyzer", () => {
  it("should detect hardcoded secrets", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("secrets-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("secrets-test");
    expect(output).toMatch(/secret|key|token/i);
  });
});

describe("Native Analyzer", () => {
  it("should detect native addons", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("native-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("native-test");
    expect(output).toMatch(/native/i);
  });
});

describe("Scripts Analyzer", () => {
  it("should detect suspicious install scripts", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("scripts-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("scripts-test");
    expect(output).toMatch(/script|install/i);
  });
});

describe("Typosquat Analyzer", () => {
  it("should detect typosquat packages", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("typosquat-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/typosquat/i);
  });
});

describe("Multiple Issues Detection", () => {
  it("should detect all issues in a package", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("multi-issue-package"),
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

describe("Clean Package", () => {
  it("should report no issues for clean package", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("clean-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/no issues|0 issues/i);
  });
});

describe("Multi-Version Package", () => {
  it("should analyze all versions of the same package", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("multi-version-package"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;

    // Should find test-package with both versions
    expect(output).toMatch(/test-package@0\.1\.0/);
    expect(output).toMatch(/test-package@0\.2\.0/);

    // Both versions should have eval issues detected
    const evalMatches = output.match(/eval/gi);
    expect(evalMatches).toBeTruthy();
    expect(evalMatches!.length).toBeGreaterThanOrEqual(2);

    // Verify both versions appear in the output
    expect(output).toContain("from v0.1.0");
    expect(output).toContain("from v0.2.0");
  });
});
