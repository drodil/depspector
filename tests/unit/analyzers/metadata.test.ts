import { describe, it, expect } from "@jest/globals";
import { MetadataAnalyzer } from "../../../src/analyzers/metadata";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("MetadataAnalyzer", () => {
  const analyzer = new MetadataAnalyzer();

  it("should detect os.userInfo()", () => {
    const code = `os.userInfo()`;
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: {},
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].type).toBe("metadata");
    expect(issues[0].message).toContain("os.userInfo");
    expect(issues[0].severity).toBe("low");
  });

  it("should detect os.networkInterfaces()", () => {
    const code = `const interfaces = os.networkInterfaces()`;
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: {},
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].message).toContain("networkInterfaces");
  });

  it("should detect os.platform()", () => {
    const code = `const platform = os.platform()`;
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: {},
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].message).toContain("platform");
  });

  it("should not flag safe os methods", () => {
    const code = `const tmpdir = os.tmpdir()`;
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: {},
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBe(0);
  });
});
