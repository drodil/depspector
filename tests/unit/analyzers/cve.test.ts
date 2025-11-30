import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { CVEAnalyzer } from "../../../src/analyzers/cve";

// Mock axios
jest.mock("axios");
const axios = require("axios");

describe("CVEAnalyzer", () => {
  const analyzer = new CVEAnalyzer();

  beforeEach(() => {
    axios.post.mockReset();
  });

  it("should detect critical CVE with CVSS score", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "CVE-2023-12345",
            summary: "Critical security vulnerability",
            severity: [
              {
                type: "CVSS_V3",
                score: "9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              },
            ],
          },
        ],
      },
    });

    const context = {
      name: "vulnerable-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(1);
    expect(issues[0].type).toBe("cve");
    expect(issues[0].severity).toBe("critical");
    expect(issues[0].message).toContain("CVE-2023-12345");
  });

  it("should detect high severity CVE", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "CVE-2023-67890",
            summary: "High severity issue",
            severity: [
              {
                type: "CVSS_V3",
                score: "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              },
            ],
          },
        ],
      },
    });

    const context = {
      name: "vulnerable-package",
      version: "2.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(1);
    expect(issues[0].severity).toBe("high");
  });

  it("should detect medium severity CVE", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "CVE-2023-11111",
            summary: "Medium severity issue",
            severity: [
              {
                type: "CVSS_V3",
                score: "5.0 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              },
            ],
          },
        ],
      },
    });

    const context = {
      name: "vulnerable-package",
      version: "3.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(1);
    expect(issues[0].severity).toBe("medium");
  });

  it("should map database severity to issue severity", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "GHSA-1234-5678-90ab",
            summary: "Security advisory",
            database_specific: {
              severity: "MODERATE",
            },
          },
        ],
      },
    });

    const context = {
      name: "vulnerable-package",
      version: "4.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(1);
    expect(issues[0].severity).toBe("medium");
  });

  it("should return no issues when package is clean", async () => {
    axios.post.mockResolvedValue({
      data: {},
    });

    const context = {
      name: "clean-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(0);
  });

  it("should handle network errors gracefully", async () => {
    axios.post.mockRejectedValue(new Error("Network error"));

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

  it("should respect enabled configuration", async () => {
    const context = {
      name: "test-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {
        analyzers: {
          cve: {
            enabled: false,
          },
        },
      },
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(0);
    expect(axios.post).not.toHaveBeenCalled();
  });

  it("should use custom timeout from config", async () => {
    axios.post.mockResolvedValue({
      data: {},
    });

    const context = {
      name: "test-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {
        analyzers: {
          cve: {
            timeout: 10000,
          },
        },
      },
    };

    await analyzer.analyze(context);
    expect(axios.post).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/query",
      expect.any(Object),
      expect.objectContaining({
        timeout: 10000,
      }),
    );
  });

  it("should handle multiple CVEs", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "CVE-2023-11111",
            summary: "First vulnerability",
            severity: [
              {
                type: "CVSS_V3",
                score: "9.0 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              },
            ],
          },
          {
            id: "CVE-2023-22222",
            summary: "Second vulnerability",
            severity: [
              {
                type: "CVSS_V3",
                score: "5.0 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
              },
            ],
          },
        ],
      },
    });

    const context = {
      name: "vulnerable-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {},
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(2);
    expect(issues[0].message).toContain("CVE-2023-11111");
    expect(issues[1].message).toContain("CVE-2023-22222");
  });

  it("should use custom CVSS thresholds", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "CVE-2023-33333",
            summary: "Score 8.5 vulnerability",
            severity: [
              {
                type: "CVSS_V3",
                score: "8.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
              },
            ],
          },
        ],
      },
    });

    const context = {
      name: "test-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: {
        analyzers: {
          cve: {
            criticalThreshold: 8.0,
            highThreshold: 6.0,
            mediumThreshold: 4.0,
          },
        },
      },
    };

    const issues = await analyzer.analyze(context);
    expect(issues.length).toBe(1);
    expect(issues[0].severity).toBe("critical"); // 8.5 >= 8.0
  });

  it("should use default thresholds when not configured", async () => {
    axios.post.mockResolvedValue({
      data: {
        vulns: [
          {
            id: "CVE-2023-44444",
            summary: "Score 8.5 vulnerability",
            severity: [
              {
                type: "CVSS_V3",
                score: "8.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
              },
            ],
          },
        ],
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
    expect(issues.length).toBe(1);
    expect(issues[0].severity).toBe("high"); // 8.5 < 9.0 but >= 7.0 (default)
  });
});
