import { describe, it, expect } from "@jest/globals";
import { BufferAnalyzer } from "../../../src/analyzers/buffer";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";

describe("BufferAnalyzer", () => {
  const analyzer = new BufferAnalyzer();

  it("should detect Buffer.from with long strings", () => {
    const code = `Buffer.from("${"A".repeat(100)}", "base64");`;
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
    expect(issues[0].type).toBe("buffer");
    expect(issues[0].message).toContain("Buffer.from");
    expect(issues[0].severity).toBe("medium");
  });

  it("should respect minBufferLength configuration", () => {
    const code = `Buffer.from("${"A".repeat(30)}", "base64");`;
    const ast = parse(code, { sourceType: "module" });
    const issues: any[] = [];

    traverse(ast, {
      enter: (path) => {
        const result = analyzer.analyze(path.node, {
          file: "test.js",
          code,
          config: {
            analyzers: {
              buffer: {
                minBufferLength: 20,
              },
            },
          },
        });
        issues.push(...result);
      },
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].message).toContain("Buffer.from");
  });

  it("should not flag short Buffer.from strings", () => {
    const code = 'Buffer.from("short", "base64");';
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
