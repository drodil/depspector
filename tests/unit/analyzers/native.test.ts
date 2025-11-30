import { describe, it, expect, beforeEach, jest } from "@jest/globals";
import { NativeAnalyzer } from "../../../src/analyzers/native";
import fs from "fs";

// Mock fs module
jest.mock("fs");

describe("NativeAnalyzer", () => {
  const analyzer = new NativeAnalyzer();

  beforeEach(() => {
    (fs.existsSync as jest.Mock).mockReset();
  });

  it("should detect binding.gyp file", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(true);

    const issues = analyzer.analyze({
      name: "native-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {},
      config: {},
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].type).toBe("native");
    expect(issues[0].message).toContain("binding.gyp");
    expect(issues[0].severity).toBe("medium");
  });

  it("should detect node-gyp dependency", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(false);

    const issues = analyzer.analyze({
      name: "native-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {
        dependencies: {
          "node-gyp": "1.0.0",
        },
      },
      config: {},
    });

    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].type).toBe("native");
    expect(issues[0].message).toContain("node-gyp");
  });

  it("should detect multiple native dependencies", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(false);

    const issues = analyzer.analyze({
      name: "native-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {
        dependencies: {
          "node-gyp": "1.0.0",
          nan: "2.0.0",
        },
      },
      config: {},
    });

    expect(issues.length).toBe(2);
  });

  it("should not flag packages without native code", () => {
    (fs.existsSync as jest.Mock).mockReturnValue(false);

    const issues = analyzer.analyze({
      name: "pure-js-package",
      version: "1.0.0",
      path: "/tmp/test",
      packageJson: {
        dependencies: {
          lodash: "4.0.0",
        },
      },
      config: {},
    });

    expect(issues.length).toBe(0);
  });
});
