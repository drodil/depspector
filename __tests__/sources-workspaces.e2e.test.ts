import { describe, it, expect } from "vitest";
import { invokeCli, getFixturePath } from "./helpers";

describe("Source Scanning (included by default)", () => {
  it("should scan project sources by default", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("sources-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("test-project");
    expect(output).toMatch(/secret/i);
    expect(output).toMatch(/eval/i);
    expect(output).toMatch(/exec|process/i);
    expect(output).toMatch(/network|https/i);
  });

  it("should NOT scan project sources with --exclude-sources", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("sources-project"),
      "--exclude-sources",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).not.toContain("index.js");
    expect(output).not.toContain("utils.js");
    expect(output).not.toContain("network.js");
  });

  it("should detect issues in nested source directories", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("sources-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/src|lib/i);
  });
});

describe("Workspaces with Array Format", () => {
  it("should scan all workspace packages by default", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/@workspace\/package1|package1/);
    expect(output).toMatch(/@workspace\/package2|package2/);
  });

  it("should detect issues in workspace package 1", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/secret|token/i);
    expect(output).toMatch(/eval/i);
  });

  it("should detect issues in workspace package 2", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/exec|process/i);
    expect(output).toMatch(/fs|file/i);
  });

  it("should NOT scan workspaces with --exclude-sources", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-project"),
      "--exclude-sources",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).not.toContain("@workspace/package1");
    expect(output).not.toContain("@workspace/package2");
  });
});

describe("Workspaces with Object Format", () => {
  it("should scan workspaces defined with object format by default", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-object-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/@monorepo\/web|web/);
    expect(output).toMatch(/@monorepo\/api|api/);
  });

  it("should detect pollution and secrets in web package", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-object-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/pollution|proto/i);
    expect(output).toMatch(/secret|aws/i);
  });

  it("should detect network and eval issues in api package", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("workspace-object-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toMatch(/network|https/i);
    expect(output).toMatch(/eval/i);
  });
});

describe("Mixed Dependencies and Sources", () => {
  it("should scan both dependencies and sources by default", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("mixed-project"),
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("evil-dep");
    expect(output).toMatch(/secret/i);
    expect(output).toContain("mixed-project");
    expect(output).toMatch(/exec|process/i);
    expect(output).toMatch(/fs|file/i);
  });

  it("should only scan dependencies with --exclude-sources", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("mixed-project"),
      "--exclude-sources",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).toContain("evil-dep");
    expect(output).not.toContain("app.js");
  });

  it("should only scan sources with --exclude-deps", () => {
    const { stdout, stderr } = invokeCli([
      "--cwd",
      getFixturePath("mixed-project"),
      "--exclude-deps",
      "--offline",
      "--cache",
      "false",
    ]);

    const output = stdout + stderr;
    expect(output).not.toContain("evil-dep");
    expect(output).toMatch(/mixed-project|local-sources/i);
    expect(output).toMatch(/exec|process/i);
  });
});
