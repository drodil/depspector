import { Node } from "@babel/types";
import { Issue } from "../analyzer";
import { AnalyzerContext, FileAnalyzerPlugin } from "./base";

export class PollutionAnalyzer implements FileAnalyzerPlugin {
  name = "pollution";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: Node, _context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (node.type === "AssignmentExpression") {
      if (
        node.left.type === "MemberExpression" &&
        node.left.property.type === "Identifier" &&
        node.left.property.name === "__proto__"
      ) {
        issues.push({
          type: "pollution",
          message: "Potential prototype pollution: Assignment to __proto__",
          severity: "critical",
          line: node.loc?.start.line,
        });
      }

      if (
        node.left.type === "MemberExpression" &&
        node.left.object.type === "MemberExpression" &&
        node.left.object.property.type === "Identifier" &&
        node.left.object.property.name === "constructor" &&
        node.left.property.type === "Identifier" &&
        node.left.property.name === "prototype"
      ) {
        issues.push({
          type: "pollution",
          message:
            "Potential prototype pollution: Assignment to constructor.prototype",
          severity: "medium",
          line: node.loc?.start.line,
        });
      }
    }

    return issues;
  }
}
