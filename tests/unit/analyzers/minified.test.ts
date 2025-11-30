import { describe, it, expect } from "@jest/globals";
import { MinifiedAnalyzer } from "../../../src/analyzers/minified";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("MinifiedAnalyzer", () => {
  const analyzer = new MinifiedAnalyzer();

  it("should detect long lines", () => {
    const longLine = "a".repeat(1001);
    const code = `const x = "${longLine}";`;
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
    expect(issues[0].type).toBe("minified");
    expect(issues[0].message).toContain("long lines");
    expect(issues[0].severity).toBe("low");
  });

  it("should detect low whitespace ratio", () => {
    const code = "constx=1;consty=2;constz=3;".repeat(50);
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
    expect(issues[0].type).toBe("minified");
  });

  it("should not flag well-formatted code", () => {
    const code = `
      const x = 1;
      const y = 2;
      const z = 3;
      
      function sum(a, b) {
        return a + b;
      }
    `;
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

  it("should not flag short files", () => {
    const code = "const x = 1";
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
