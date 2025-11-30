import { PackageAnalyzerPlugin, PackageContext } from "./base";
import { Issue } from "../analyzer";

const POPULAR_PACKAGES = [
  "react",
  "react-dom",
  "vue",
  "angular",
  "express",
  "lodash",
  "moment",
  "axios",
  "tslib",
  "commander",
  "chalk",
  "debug",
  "inquirer",
  "fs-extra",
  "body-parser",
  "cors",
  "dotenv",
  "uuid",
  "aws-sdk",
  "webpack",
  "eslint",
  "prettier",
  "typescript",
  "jest",
  "mocha",
  "chai",
  "supertest",
  "nodemon",
  "rimraf",
  "glob",
];

export class TyposquatAnalyzer implements PackageAnalyzerPlugin {
  name = "typosquat";
  type = "package" as const;
  requiresNetwork = false;

  analyze(context: PackageContext): Issue[] {
    const issues: Issue[] = [];
    const pkgName = context.name;

    /* eslint-disable-next-line */
    if (/[^\x00-\x7F]/.test(pkgName)) {
      issues.push({
        type: "typosquat",
        message: `Package name contains non-ASCII characters (potential homoglyph attack)`,
        severity: "high",
      });
    }

    for (const popular of POPULAR_PACKAGES) {
      if (pkgName === popular) {
        continue;
      }

      const distance = this.levenshtein(pkgName, popular);
      const similarity =
        1 - distance / Math.max(pkgName.length, popular.length);

      if (distance <= 2 && similarity > 0.8) {
        issues.push({
          type: "typosquat",
          message: `Package name '${pkgName}' is very similar to popular package '${popular}' (Levenshtein distance: ${distance})`,
          severity: "high",
        });
      }
    }

    return issues;
  }

  private levenshtein(a: string, b: string): number {
    const matrix = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1),
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }
}
