import { Issue } from "../analyzer";
import { PackageAnalyzerPlugin, PackageContext } from "./base";

export class ScriptsAnalyzer implements PackageAnalyzerPlugin {
  name = "scripts";
  type = "package" as const;
  requiresNetwork = false;

  analyze(context: PackageContext): Issue[] {
    const issues: Issue[] = [];
    const scripts = context.packageJson.scripts || {};

    const suspiciousLifecycleEvents = [
      "preinstall",
      "install",
      "postinstall",
      "prepublish",
      "prepare",
    ];

    for (const event of suspiciousLifecycleEvents) {
      if (scripts[event]) {
        issues.push({
          type: "scripts",
          message: `Package uses suspicious lifecycle script: "${event}". This is a common vector for malware.`,
          severity: "medium",
          code: scripts[event],
        });
      }
    }

    return issues;
  }
}
