import { describe, it, expect } from "@jest/globals";
import { TyposquatAnalyzer } from "../../../src/analyzers/typosquat";

describe("TyposquatAnalyzer", () => {
  const analyzer = new TyposquatAnalyzer();

  it("should detect similar package names", async () => {
    const context = {
      name: "reactt", // 1 char difference, very similar
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].type).toBe("typosquat");
    expect(issues[0].message).toContain("react");
  });

  it("should detect homoglyphs", async () => {
    const context = {
      name: "rеact", // Cyrillic 'e'
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].message).toContain("non-ASCII");
  });

  it("should not flag legitimate packages", async () => {
    const context = {
      name: "my-unique-package-name-12345",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(0);
  });
});
