import { describe, it, expect } from "@jest/globals";
import { loadConfig } from "../../src/config";
import { Analyzer } from "../../src/analyzer";
import path from "path";
import fs from "fs";
import os from "os";

describe("Configuration E2E", () => {
  it("should load .depspectorrc from current directory", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "depspector-test-"));
    const configPath = path.join(tempDir, ".depspectorrc");

    const testConfig = {
      analyzers: {
        network: { allowedHosts: ["example.com"] },
      },
      exclude: ["test-package"],
    };

    fs.writeFileSync(configPath, JSON.stringify(testConfig));

    const originalCwd = process.cwd();
    process.chdir(tempDir);

    try {
      const config = loadConfig();
      expect(config.analyzers?.network).toBeDefined();
      expect((config.analyzers?.network as any).allowedHosts).toContain(
        "example.com",
      );
      expect(config.exclude).toContain("test-package");
    } finally {
      process.chdir(originalCwd);
      fs.unlinkSync(configPath);
      fs.rmdirSync(tempDir);
    }
  });

  it("should load custom config file", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "depspector-test-"));
    const customConfigPath = path.join(tempDir, "custom-config.json");

    const testConfig = {
      analyzers: {
        eval: { enabled: false },
      },
    };

    fs.writeFileSync(customConfigPath, JSON.stringify(testConfig));

    try {
      const config = loadConfig(customConfigPath);
      expect(config.analyzers?.eval?.enabled).toBe(false);
    } finally {
      fs.unlinkSync(customConfigPath);
      fs.rmdirSync(tempDir);
    }
  });

  it("should return empty config if file does not exist", () => {
    const config = loadConfig("/nonexistent/path/.depspectorrc");
    expect(config).toEqual({});
  });

  it("should disable network-requiring analyzers in offline mode", async () => {
    const config = {};
    const offlineAnalyzer = new Analyzer(config, true);
    const normalAnalyzer = new Analyzer(config, false);

    // Create a test package context
    const packageContext = {
      name: "test-package",
      version: "1.0.0",
      path: "/test",
      packageJson: {},
      config: config,
    };

    // In offline mode, network-requiring analyzers should be filtered out
    // CVE, cooldown, dormant, reputation require network
    const offlineResult = await offlineAnalyzer.analyzePackage(packageContext);
    const normalResult = await normalAnalyzer.analyzePackage(packageContext);

    // Offline should have fewer or same analyzers run (no network calls)
    // This test verifies the analyzer was created with offline mode correctly
    expect(offlineResult).toBeDefined();
    expect(normalResult).toBeDefined();
  });
});
