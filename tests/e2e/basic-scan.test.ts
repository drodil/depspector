import { describe, it, expect } from "@jest/globals";
import { Analyzer } from "../../src/analyzer";
import path from "path";
import fs from "fs";

describe("Basic Scan E2E", () => {
  it("should detect issues in malicious-package fixture", () => {
    const analyzer = new Analyzer();
    const fixturePath = path.join(
      __dirname,
      "../fixtures/malicious-package/index.js",
    );
    const code = fs.readFileSync(fixturePath, "utf-8");

    const result = analyzer.analyzeFile(fixturePath, code);

    expect(result.issues.length).toBeGreaterThan(0);

    // Should detect process.env access
    expect(result.issues.some((i) => i.type === "env")).toBe(true);

    // Should detect network call
    expect(result.issues.some((i) => i.type === "network")).toBe(true);

    // Should detect eval
    expect(result.issues.some((i) => i.type === "eval")).toBe(true);
  });

  it("should respect configuration", () => {
    const analyzer = new Analyzer({
      analyzers: {
        env: { enabled: false },
      },
    });

    const fixturePath = path.join(
      __dirname,
      "../fixtures/malicious-package/index.js",
    );
    const code = fs.readFileSync(fixturePath, "utf-8");

    const result = analyzer.analyzeFile(fixturePath, code);

    // Should NOT detect env issues
    expect(result.issues.some((i) => i.type === "env")).toBe(false);

    // But should still detect other issues
    expect(result.issues.length).toBeGreaterThan(0);
  });
});
