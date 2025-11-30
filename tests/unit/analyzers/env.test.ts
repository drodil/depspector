import { describe, it, expect, beforeEach } from "@jest/globals";
import { EnvAnalyzer } from "../../../src/analyzers/env";
import { clearRegistryCache } from "../../../src/registryUtil"; // no-op for env but keeps consistency
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("EnvAnalyzer", () => {
  const analyzer = new EnvAnalyzer();

  beforeEach(() => {
    clearRegistryCache();
  });

  it("should detect process.env access to variable", () => {
    const code = "const secret = process.env.AWS_SECRET_KEY;";
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
    expect(issues[0].type).toBe("env");
    expect(issues[0].severity).toBe("medium");
  });

  it("should not flag other property access", () => {
    const code = "const value = someObject.env.value;";
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

  it("should not report whitelisted env variable access", () => {
    const code = "const secret = process.env.ALLOWED_KEY;";
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: { analyzers: { env: { allowedVariables: ["ALLOWED_KEY"] } } },
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBe(0);
  });
});
