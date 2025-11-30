import { PackageAnalyzerPlugin, PackageContext } from "./base";
import { Issue } from "../analyzer";
import { fetchPackageMetadata } from "../registryUtil";

export class ReputationAnalyzer implements PackageAnalyzerPlugin {
  name = "reputation";
  type = "package" as const;
  requiresNetwork = true;

  async analyze(context: PackageContext): Promise<Issue[]> {
    const issues: Issue[] = [];
    const { name, version, config } = context;

    const data = await fetchPackageMetadata(name, config);
    if (!data) {
      return issues;
    }
    const versionData = data.versions[version];
    if (!versionData) {
      return issues;
    }
    const maintainers = data.maintainers || [];
    const publisher = versionData._npmUser;
    const whitelistedUsers =
      config.analyzers?.reputation?.whitelistedUsers || [];
    if (publisher && whitelistedUsers.includes(publisher.name)) {
      return issues;
    }
    if (maintainers.length === 1) {
      issues.push({
        type: "reputation",
        message: `Package has a single maintainer.`,
        severity: "low",
      });
    }
    const isMaintainer = maintainers.some(
      (m: any) => m.name === publisher?.name,
    );
    if (publisher && !isMaintainer) {
      issues.push({
        type: "reputation",
        message: `Version published by user '${publisher.name}' who is not listed as a maintainer.`,
        severity: "high",
      });
    }

    return issues;
  }
}
