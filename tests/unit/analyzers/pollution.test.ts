import { describe, it, expect } from "@jest/globals";
import { PollutionAnalyzer } from "../../../src/analyzers/pollution";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("PollutionAnalyzer", () => {
  const analyzer = new PollutionAnalyzer();

  it("should detect __proto__ assignment", () => {
    const code = `obj.__proto__ = {}`;
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
    expect(issues[0].type).toBe("pollution");
    expect(issues[0].message).toContain("__proto__");
    expect(issues[0].severity).toBe("critical");
  });

  it("should detect constructor.prototype assignment", () => {
    const code = `obj.constructor.prototype = malicious`;
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
    expect(issues[0].type).toBe("pollution");
    expect(issues[0].message).toContain("constructor.prototype");
    expect(issues[0].severity).toBe("medium");
  });

  it("should not flag safe object assignments", () => {
    const code = `obj.property = 'value'`;
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
