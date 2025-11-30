import { describe, it, expect } from "@jest/globals";
import { SecretsAnalyzer } from "../../../src/analyzers/secrets";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("SecretsAnalyzer", () => {
  const analyzer = new SecretsAnalyzer();

  it("should detect AWS access key", () => {
    const code = `const key = "AKIAIOSFODNN7EXAMPLE"`;
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
    expect(issues[0].type).toBe("secrets");
    expect(issues[0].message).toContain("AWS");
    expect(issues[0].severity).toBe("critical");
  });

  it("should detect RSA private key", () => {
    const code = `const key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."`;
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
    expect(issues[0].type).toBe("secrets");
    expect(issues[0].message).toContain("Private Key");
  });

  it("should detect Stripe secret key", () => {
    const code = `const key = "sk_live_1234567890abcdef"`;
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
    expect(issues[0].type).toBe("secrets");
    expect(issues[0].message).toContain("Stripe");
  });

  it("should not flag safe strings", () => {
    const code = `const message = "Hello, world!"`;
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
