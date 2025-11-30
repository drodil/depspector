import chalk from "chalk";
import { AnalysisResult } from "./analyzer";
import { DiffResult } from "./differ";

export class Reporter {
  private severityLevels = { critical: 4, high: 3, medium: 2, low: 1 };

  private shouldReportSeverity(
    severity: string,
    reportLevel?: "critical" | "high" | "medium" | "low",
  ): boolean {
    if (!reportLevel) return true;
    return (
      this.severityLevels[severity as "critical" | "high" | "medium" | "low"] >=
      this.severityLevels[reportLevel]
    );
  }

  printReport(
    results: AnalysisResult[],
    diffs: DiffResult[] = [],
    reportLevel?: "critical" | "high" | "medium" | "low",
    onlyNew: boolean = false,
  ) {
    console.log(chalk.bold.underline("\nDepspector Security Report\n"));

    const filteredResults = onlyNew
      ? results.filter((r) => !r.isFromCache)
      : results;

    if (filteredResults.length === 0) {
      if (onlyNew && results.length > 0) {
        console.log(
          chalk.green(
            "No new issues detected. All found issues were from previous scan.",
          ),
        );
      } else {
        console.log(chalk.green("No suspicious patterns detected."));
      }
      return;
    }

    let issueCount = 0;
    let newIssueCount = 0;
    let totalIssueCount = 0;
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

    filteredResults.forEach((result) => {
      if (result.issues.length === 0) {
        return;
      }

      if (result.package) {
        console.log(
          chalk.bold.magenta(
            `Package: ${result.package} (${result.issues.length} issues)`,
          ),
        );
      } else if (result.file) {
        console.log(
          chalk.bold.white(
            `File: ${result.file} (${result.issues.length} issues)`,
          ),
        );
      }

      const diff = result.file
        ? diffs.find((d) => d.file === result.file)
        : null;
      if (diff) {
        console.log(chalk.yellow(`  [${diff.changeType.toUpperCase()}]`));
      }

      result.issues.forEach((issue) => {
        if (!this.shouldReportSeverity(issue.severity, reportLevel)) {
          return;
        }

        if (diffs.length > 0 && !result.package) {
          if (diff && issue.line !== undefined) {
            const isChanged = diff.changedLines.some(
              (range) =>
                (issue.line as number) >= range.start &&
                (issue.line as number) <= range.end,
            );
            if (!isChanged) {
              return;
            }
          }
        }

        issueCount++;
        if (!result.isFromCache) {
          newIssueCount++;
        }
        const color = this.getSeverityColor(issue.severity);
        const lineInfo = issue.line ? chalk.gray(`(Line ${issue.line})`) : "";
        const idInfo = issue.id ? chalk.gray(`[ID: ${issue.id}]`) : "";
        console.log(
          `  ${color(`[${issue.severity.toUpperCase()}]`)} ${issue.message} ${lineInfo} ${idInfo}`,
        );
        if (issue.code) {
          console.log(chalk.gray(`    > ${issue.code.trim()}`));
        }
      });
      console.log("");
    });

    // Count total issues across all results (including cached)
    results.forEach((result) => {
      result.issues.forEach((issue) => {
        if (!this.shouldReportSeverity(issue.severity, reportLevel)) {
          return;
        }

        if (diffs.length > 0 && !result.package) {
          const diff = result.file
            ? diffs.find((d) => d.file === result.file)
            : null;
          if (diff && issue.line !== undefined) {
            const isChanged = diff.changedLines.some(
              (range) =>
                (issue.line as number) >= range.start &&
                (issue.line as number) <= range.end,
            );
            if (!isChanged) {
              return;
            }
          }
        }

        totalIssueCount++;
        severityCounts[
          issue.severity as "critical" | "high" | "medium" | "low"
        ]++;
      });
    });

    if (issueCount > 0) {
      const severityBreakdown = [
        severityCounts.critical > 0 && `${severityCounts.critical} critical`,
        severityCounts.high > 0 && `${severityCounts.high} high`,
        severityCounts.medium > 0 && `${severityCounts.medium} medium`,
        severityCounts.low > 0 && `${severityCounts.low} low`,
      ]
        .filter(Boolean)
        .join(", ");

      if (onlyNew) {
        console.log(
          chalk.red.bold(
            `Found ${issueCount} new potential issues. (${severityBreakdown})`,
          ),
        );
      } else {
        console.log(
          chalk.red.bold(
            `Found ${totalIssueCount} potential issues. (${severityBreakdown})`,
          ),
        );
        if (newIssueCount < totalIssueCount) {
          console.log(chalk.gray(`(New: ${newIssueCount} potential issues)`));
        }
      }

      const criticalIssues = results
        .flatMap((result) =>
          result.issues
            .filter((issue) => issue.severity === "critical")
            .map((issue) => ({
              package: result.package,
              file: result.file,
              issue,
            })),
        )
        .filter((item) => {
          if (
            onlyNew &&
            results.find(
              (r) => r.file === item.file || r.package === item.package,
            )?.isFromCache
          ) {
            return false;
          }
          return this.shouldReportSeverity(item.issue.severity, reportLevel);
        });

      if (criticalIssues.length > 0) {
        console.log("");
        console.log(
          chalk.bgRed.white.bold(
            ` ⚠ CRITICAL SECURITY ISSUES (${criticalIssues.length}) `,
          ),
        );
        console.log(chalk.red("These issues require immediate attention:\n"));

        criticalIssues.forEach(({ package: pkg, file, issue }) => {
          const location = pkg || file || "unknown";
          const lineInfo = issue.line ? ` (Line ${issue.line})` : "";
          const idInfo = issue.id ? chalk.gray(` [ID: ${issue.id}]`) : "";
          console.log(chalk.red.bold(`  • ${location}${lineInfo}${idInfo}`));
          console.log(chalk.red(`    ${issue.message}`));
        });
        console.log("");
      }
    } else {
      console.log(
        chalk.green("No suspicious patterns detected in changed code."),
      );
    }

    return issueCount;
  }

  hasIssuesAtLevel(
    results: AnalysisResult[],
    level: "critical" | "high" | "medium" | "low",
  ): boolean {
    return results.some((result) =>
      result.issues.some(
        (issue) =>
          this.severityLevels[
            issue.severity as "critical" | "high" | "medium" | "low"
          ] >= this.severityLevels[level],
      ),
    );
  }

  private getSeverityColor(severity: string) {
    switch (severity) {
      case "critical":
        return chalk.red.bold;
      case "high":
        return chalk.red;
      case "medium":
        return chalk.yellow;
      case "low":
        return chalk.blue;
      default:
        return chalk.white;
    }
  }
}
