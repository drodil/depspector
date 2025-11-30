import fs from "fs";
import path from "path";
import { Issue } from "../analyzer";
import { PackageAnalyzerPlugin, PackageContext } from "./base";

export class NativeAnalyzer implements PackageAnalyzerPlugin {
  name = "native";
  type = "package" as const;
  requiresNetwork = false;

  analyze(context: PackageContext): Issue[] {
    const issues: Issue[] = [];

    if (fs.existsSync(path.join(context.path, "binding.gyp"))) {
      issues.push({
        type: "native",
        message:
          "Package contains native code (binding.gyp). Native modules can execute arbitrary code during build.",
        severity: "medium",
      });
    }

    const nativeDeps = [
      "node-gyp",
      "node-pre-gyp",
      "prebuild-install",
      "nan",
      "cmake-js",
    ];
    const allDeps = {
      ...context.packageJson.dependencies,
      ...context.packageJson.devDependencies,
    };

    for (const dep of nativeDeps) {
      if (allDeps[dep]) {
        issues.push({
          type: "native",
          message: `Package depends on native build tool: "${dep}".`,
          severity: "medium",
        });
      }
    }

    return issues;
  }
}
