import { describe, it, expect } from "@jest/globals";
import { FsAnalyzer } from "../../../src/analyzers/fs";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("FsAnalyzer", () => {
  const analyzer = new FsAnalyzer();

  it("should detect /etc/passwd access", () => {
    const code = 'fs.readFileSync("/etc/passwd");';
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
    expect(issues[0].type).toBe("fs");
    expect(issues[0].severity).toBe("high");
    expect(issues[0].message).toContain("/etc/passwd");
  });

  it("should detect .ssh access", () => {
    const code = 'fs.readFileSync("~/.ssh/id_rsa");';
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
    expect(issues[0].message).toContain(".ssh");
  });

  it("should detect file write operations", () => {
    const code = 'fs.writeFileSync("test.txt", "data");';
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
    expect(issues[0].type).toBe("fs");
    expect(issues[0].severity).toBe("medium");
  });
});
