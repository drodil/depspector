import { Node } from "@babel/types";
import { Issue } from "../analyzer";
import { AnalyzerContext, FileAnalyzerPlugin } from "./base";

export class ProcessAnalyzer implements FileAnalyzerPlugin {
  name = "process";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: Node, _context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (node.type === "CallExpression") {
      if (
        node.callee.type === "MemberExpression" &&
        node.callee.object.type === "CallExpression" &&
        node.callee.object.callee.type === "Identifier" &&
        node.callee.object.callee.name === "require" &&
        node.callee.object.arguments.length > 0 &&
        node.callee.object.arguments[0].type === "StringLiteral" &&
        node.callee.object.arguments[0].value === "child_process"
      ) {
        issues.push({
          type: "process",
          message: `Suspicious process spawning detected via child_process.${
            (node.callee.property as any).name
          }`,
          severity: "critical",
          line: node.loc?.start.line,
        });
      }

      if (
        node.callee.type === "MemberExpression" &&
        node.callee.object.type === "Identifier" &&
        node.callee.object.name === "process" &&
        node.callee.property.type === "Identifier" &&
        node.callee.property.name === "binding" &&
        node.arguments.length > 0 &&
        node.arguments[0].type === "StringLiteral" &&
        node.arguments[0].value === "spawn_sync"
      ) {
        issues.push({
          type: "process",
          message:
            "Low-level process spawning detected via process.binding('spawn_sync')",
          severity: "critical",
          line: node.loc?.start.line,
        });
      }
    }

    return issues;
  }
}
