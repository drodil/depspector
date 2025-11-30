import { describe, it, expect } from "@jest/globals";
import { NetworkAnalyzer } from "../../../src/analyzers/network";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("NetworkAnalyzer", () => {
  const analyzer = new NetworkAnalyzer();

  it("should detect fetch calls", () => {
    const code = 'fetch("https://evil.com");';
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
    expect(issues[0].type).toBe("network");
    expect(issues[0].message).toContain("fetch");
  });

  it("should respect whitelist", () => {
    const code = 'fetch("https://google.com");';
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: {
            analyzers: {
              network: { allowedHosts: ["google.com"] },
            },
          },
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBe(0);
  });

  it("should detect axios calls", () => {
    const code = 'axios.get("https://suspicious.io");';
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
    expect(issues[0].type).toBe("network");
  });
});
