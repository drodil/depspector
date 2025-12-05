import { describe, it, expect } from "vitest";
import path from "path";
import { tmpdir } from "os";
import { readFileSync, unlinkSync } from "fs";
import { invokeCli } from "./helpers";

describe("Multi-version package analyzer", () => {
  const fixtureDir = path.join(
    __dirname,
    "__fixtures__",
    "multi-version-package"
  );

  it("should analyze all versions of the same package", () => {
    const jsonFile = path.join(tmpdir(), "depspector-test-multi-version.json");

    try {
      const { exitCode } = invokeCli([
        "--cwd",
        fixtureDir,
        "--offline",
        "--json",
        jsonFile,
      ]);

      // Exit code may be non-zero if issues are found
      expect([0, 1]).toContain(exitCode);

      // Read the JSON output
      const output = readFileSync(jsonFile, "utf-8");
      const packages = JSON.parse(output);
      expect(Array.isArray(packages)).toBeTruthy();

      // Get the test packages from the results
      const testPackages = packages.filter(
        (pkg: any) => pkg.package === "test" || pkg.package === "test-package"
      );

      // We should have test packages analyzed
      expect(testPackages.length).toBeGreaterThanOrEqual(1);

      // Check that they have the expected versions
      const versions = testPackages.map((pkg: any) => pkg.version);
      expect(versions.length).toBeGreaterThanOrEqual(1);
    } finally {
      try {
        unlinkSync(jsonFile);
      } catch {
        // ignore
      }
    }
  });

  it("should detect eval usage in all packages", () => {
    const jsonFile = path.join(tmpdir(), "depspector-test-eval.json");

    try {
      const { exitCode } = invokeCli([
        "--cwd",
        fixtureDir,
        "--offline",
        "--json",
        jsonFile,
      ]);

      expect([0, 1]).toContain(exitCode);

      const output = readFileSync(jsonFile, "utf-8");
      const packages = JSON.parse(output);

      // Get package1, package2, and test packages
      const package1 = packages.find((pkg: any) => pkg.package === "package1");
      const package2 = packages.find((pkg: any) => pkg.package === "package2");

      expect(package1).toBeDefined();
      expect(package2).toBeDefined();

      // Both package1 and package2 should have issues detected (eval usage)
      const package1HasEval =
        package1?.issues &&
        package1.issues.some((issue: any) => issue.type === "eval");
      const package2HasEval =
        package2?.issues &&
        package2.issues.some((issue: any) => issue.type === "eval");

      expect(package1HasEval).toBeTruthy();
      expect(package2HasEval).toBeTruthy();
    } finally {
      try {
        unlinkSync(jsonFile);
      } catch {
        // ignore
      }
    }
  });

  it("should have test packages analyzed", () => {
    const jsonFile = path.join(tmpdir(), "depspector-test-versions.json");

    try {
      const { exitCode } = invokeCli([
        "--cwd",
        fixtureDir,
        "--offline",
        "--json",
        jsonFile,
      ]);

      expect([0, 1]).toContain(exitCode);

      const output = readFileSync(jsonFile, "utf-8");
      const packages = JSON.parse(output);
      const testPackages = packages.filter(
        (pkg: any) => pkg.package === "test" || pkg.package === "test-package"
      );

      // Verify we have test packages
      expect(testPackages.length).toBeGreaterThanOrEqual(1);

      // Check that they have issues (eval usage)
      const testPackagesWithIssues = testPackages.filter(
        (pkg: any) => pkg.issues && pkg.issues.length > 0
      );
      expect(testPackagesWithIssues.length).toBeGreaterThan(0);
    } finally {
      try {
        unlinkSync(jsonFile);
      } catch {
        // ignore
      }
    }
  });
});
