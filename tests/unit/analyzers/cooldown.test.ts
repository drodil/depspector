import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { CooldownAnalyzer } from "../../../src/analyzers/cooldown";
import { DormantAnalyzer } from "../../../src/analyzers/dormant";
import { clearRegistryCache } from "../../../src/registryUtil";

// Mock axios
jest.mock("axios");
const axios = require("axios");

describe("CooldownAnalyzer", () => {
  const analyzer = new CooldownAnalyzer();

  beforeEach(() => {
    clearRegistryCache();
    axios.get.mockReset();
  });

  it("should detect fresh packages", async () => {
    const now = new Date();
    const recentDate = new Date(now.getTime() - 1000 * 60 * 60 * 24); // 24h ago

    axios.get.mockResolvedValue({
      data: {
        time: {
          "1.0.0": recentDate.toISOString(),
          modified: now.toISOString(),
        },
      },
    });

    const context = {
      name: "test-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBeGreaterThan(0);
    expect(issues[0].type).toBe("cooldown");
    expect(issues[0].message).toContain("72 hours");
  });

  it("should handle network errors gracefully", async () => {
    axios.get.mockRejectedValue(new Error("Network error"));
    const context = {
      name: "test-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };
    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(0);
  });
});

describe("DormantAnalyzer", () => {
  const analyzer = new DormantAnalyzer();

  beforeEach(() => {
    clearRegistryCache();
    axios.get.mockReset();
  });

  it("should detect dormant packages", async () => {
    const now = new Date();
    const longAgo = new Date(now.getTime() - 400 * 24 * 60 * 60 * 1000); // 400 days ago
    const recent = now.toISOString();
    axios.get.mockResolvedValue({
      data: {
        time: {
          "1.0.0": longAgo.toISOString(),
          "2.0.0": recent,
          modified: recent,
        },
      },
    });
    const context = {
      name: "test-package",
      version: "2.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };
    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(1);
    expect(issues[0].type).toBe("dormant");
  });
});
