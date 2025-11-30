import { describe, it, expect } from "@jest/globals";
import { ProcessAnalyzer } from "../../../src/analyzers/process";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("ProcessAnalyzer", () => {
  const analyzer = new ProcessAnalyzer();

  it("should detect child_process.exec usage", () => {
    const code = `require('child_process').exec('rm -rf /')`;
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
    expect(issues[0].type).toBe("process");
    expect(issues[0].message).toContain("child_process");
    expect(issues[0].severity).toBe("critical");
  });

  it("should detect process.binding spawn_sync", () => {
    const code = `process.binding('spawn_sync')`;
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
    expect(issues[0].type).toBe("process");
    expect(issues[0].message).toContain("process.binding");
    expect(issues[0].severity).toBe("critical");
  });

  it("should not flag safe code", () => {
    const code = `const result = calculateSum(1, 2)`;
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
