import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

export class DynamicAnalyzer implements FileAnalyzerPlugin {
  name = "dynamic";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (t.isCallExpression(node) && t.isMemberExpression(node.callee)) {
      const objectName = t.isIdentifier(node.callee.object)
        ? node.callee.object.name
        : "";
      const propertyName = t.isIdentifier(node.callee.property)
        ? node.callee.property.name
        : "";

      if (objectName === "vm" && propertyName.startsWith("runIn")) {
        issues.push({
          type: "dynamic",
          line: node.loc?.start.line || 0,
          message: `Dynamic code execution detected (vm.${propertyName})`,
          severity: "critical",
          code: getLine(node, context),
        });
      }
    }

    if (
      t.isCallExpression(node) &&
      t.isIdentifier(node.callee, { name: "require" })
    ) {
      if (node.arguments.length > 0 && !t.isStringLiteral(node.arguments[0])) {
        issues.push({
          type: "dynamic",
          line: node.loc?.start.line || 0,
          message: `Dynamic require detected (argument is not a string literal)`,
          severity: "medium",
          code: getLine(node, context),
        });
      } else if (
        node.arguments.length > 0 &&
        t.isBinaryExpression(node.arguments[0])
      ) {
        issues.push({
          type: "dynamic",
          line: node.loc?.start.line || 0,
          message: `Dynamic require detected (concatenated string)`,
          severity: "medium",
          code: getLine(node, context),
        });
      }
    }

    return issues;
  }
}
