import { describe, it, expect } from "@jest/globals";
import { ObfuscationAnalyzer } from "../../../src/analyzers/obfuscation";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("ObfuscationAnalyzer", () => {
  const analyzer = new ObfuscationAnalyzer();

  it("should detect long strings", () => {
    const longString = "A".repeat(200);
    const code = `const payload = "${longString}";`;
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
    expect(issues[0].type).toBe("obfuscation");
    expect(issues[0].severity).toBe("low");
  });

  it("should not flag short strings", () => {
    const code = 'const name = "John Doe";';
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
