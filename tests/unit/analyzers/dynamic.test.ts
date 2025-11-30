import { describe, it, expect } from "@jest/globals";
import { DynamicAnalyzer } from "../../../src/analyzers/dynamic";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("DynamicAnalyzer", () => {
  const analyzer = new DynamicAnalyzer();

  it("should detect vm.runInContext", () => {
    const code = 'vm.runInNewContext("malicious");';
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
    expect(issues[0].severity).toBe("critical");
  });

  it("should detect dynamic require", () => {
    const code = 'require("path" + variable);';
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
    expect(issues[0].message).toContain("Dynamic require");
  });
});
