import { describe, it, expect } from "@jest/globals";
import { EvalAnalyzer } from "../../../src/analyzers/eval";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("EvalAnalyzer", () => {
  const analyzer = new EvalAnalyzer();

  it("should detect eval() usage", () => {
    const code = 'eval("malicious code");';
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
    expect(issues[0].type).toBe("eval");
    expect(issues[0].severity).toBe("critical");
    expect(issues[0].message).toContain("eval()");
  });

  it("should detect new Function()", () => {
    const code = 'const fn = new Function("return 1");';
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
    expect(issues[0].type).toBe("eval");
    expect(issues[0].message).toContain("new Function");
  });

  it("should not flag regular functions", () => {
    const code = "function test() { return 1; }";
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
