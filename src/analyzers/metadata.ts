import { Node } from "@babel/types";
import { Issue } from "../analyzer";
import { AnalyzerContext, FileAnalyzerPlugin } from "./base";

export class MetadataAnalyzer implements FileAnalyzerPlugin {
  name = "metadata";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: Node, _context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (node.type === "CallExpression") {
      if (
        node.callee.type === "MemberExpression" &&
        node.callee.object.type === "Identifier" &&
        node.callee.object.name === "os" &&
        node.callee.property.type === "Identifier"
      ) {
        const method = node.callee.property.name;
        const suspiciousMethods = [
          "userInfo",
          "networkInterfaces",
          "platform",
          "hostname",
          "release",
        ];

        if (suspiciousMethods.includes(method)) {
          issues.push({
            type: "metadata",
            message: `Suspicious system metadata collection detected: os.${method}()`,
            severity: "low",
            line: node.loc?.start.line,
          });
        }
      }
    }

    return issues;
  }
}
