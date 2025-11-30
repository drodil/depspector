import { PackageAnalyzerPlugin, PackageContext } from "./base";
import { Issue } from "../analyzer";
import { fetchPackageMetadata } from "../registryUtil";

export class CooldownAnalyzer implements PackageAnalyzerPlugin {
  name = "cooldown";
  type = "package" as const;
  requiresNetwork = true;

  async analyze(context: PackageContext): Promise<Issue[]> {
    const issues: Issue[] = [];
    const { name, version, config } = context;

    const cooldownConfig = config.analyzers?.cooldown;
    const hoursSincePublishThreshold = cooldownConfig?.hoursSincePublish ?? 72;

    const metadata = await fetchPackageMetadata(name, config);
    if (!metadata) {
      return [];
    }
    const time = metadata.time || {};
    const created = time[version];
    if (!created) {
      return [];
    }
    const publishDate = new Date(created);
    const now = new Date();
    const hoursSincePublish =
      (now.getTime() - publishDate.getTime()) / (1000 * 60 * 60);

    if (hoursSincePublish < hoursSincePublishThreshold) {
      issues.push({
        type: "cooldown",
        message: `Package version ${version} was published less than ${hoursSincePublishThreshold} hours ago (${hoursSincePublish.toFixed(1)}h).`,
        severity: "medium",
      });
    }

    return issues;
  }
}
