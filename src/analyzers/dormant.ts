import { PackageAnalyzerPlugin, PackageContext } from "./base";
import { Issue } from "../analyzer";
import { fetchPackageMetadata } from "../registryUtil";

export class DormantAnalyzer implements PackageAnalyzerPlugin {
  name = "dormant";
  type = "package" as const;
  requiresNetwork = true;

  async analyze(context: PackageContext): Promise<Issue[]> {
    const issues: Issue[] = [];
    const { name, version, config } = context;

    const dormantConfig = config.analyzers?.dormant;
    const daysSincePreviousPublishThreshold =
      dormantConfig?.daysSincePreviousPublish ?? 365;

    const metadata = await fetchPackageMetadata(name, context.config);
    if (!metadata) {
      return [];
    }
    const time = metadata.time || {};
    const currentDateStr = time[version];
    if (!currentDateStr) {
      return [];
    }
    const publishDate = new Date(currentDateStr);
    const versions = Object.keys(time).filter(
      (v) => v !== "modified" && v !== "created" && v !== version,
    );
    if (versions.length === 0) {
      return [];
    }
    versions.sort(
      (a, b) => new Date(time[b]).getTime() - new Date(time[a]).getTime(),
    );
    const previousVersion = versions[0];
    const previousDate = new Date(time[previousVersion]);
    const daysSincePrevious =
      (publishDate.getTime() - previousDate.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSincePrevious > daysSincePreviousPublishThreshold) {
      issues.push({
        type: "dormant",
        message: `Package was dormant for ${daysSincePrevious.toFixed(0)} days before this update. Sudden update after long dormancy is suspicious.`,
        severity: "high",
      });
    }
    return issues;
  }
}
