import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { ReputationAnalyzer } from "../../../src/analyzers/reputation";
import { clearRegistryCache } from "../../../src/registryUtil";

// Mock axios
jest.mock("axios");
const axios = require("axios");

describe("ReputationAnalyzer", () => {
  const analyzer = new ReputationAnalyzer();

  beforeEach(() => {
    clearRegistryCache();
    axios.get.mockReset();
  });

  it("should detect single maintainer", async () => {
    axios.get.mockResolvedValue({
      data: {
        maintainers: [{ name: "single-dev", email: "dev@test.com" }],
        versions: {
          "1.0.0": {
            _npmUser: { name: "single-dev" },
            dist: {},
          },
        },
        "dist-tags": { latest: "1.0.0" },
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
    expect(issues.some((i) => i.message.includes("single maintainer"))).toBe(
      true,
    );
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
