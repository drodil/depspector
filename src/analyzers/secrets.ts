import { Node } from "@babel/types";
import { Issue } from "../analyzer";
import { AnalyzerContext, FileAnalyzerPlugin } from "./base";

export class SecretsAnalyzer implements FileAnalyzerPlugin {
  name = "secrets";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: Node, _context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (node.type === "StringLiteral") {
      const value = node.value;

      if (/AKIA[0-9A-Z]{16}/.test(value)) {
        issues.push({
          type: "secrets",
          message: "Potential AWS Access Key ID found",
          severity: "critical",
          line: node.loc?.start.line,
        });
      }

      if (value.includes("BEGIN RSA PRIVATE KEY")) {
        issues.push({
          type: "secrets",
          message: "Potential RSA Private Key found",
          severity: "critical",
          line: node.loc?.start.line,
        });
      }

      if (value.startsWith("sk_live_")) {
        issues.push({
          type: "secrets",
          message: "Potential Stripe Secret Key found",
          severity: "critical",
          line: node.loc?.start.line,
        });
      }
    }

    return issues;
  }
}
