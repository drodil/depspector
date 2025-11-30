import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

export class EnvAnalyzer implements FileAnalyzerPlugin {
  name = "env";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];
    const allowed = context.config.analyzers?.env?.allowedVariables || [];

    if (t.isMemberExpression(node)) {
      if (
        t.isMemberExpression(node.object) &&
        t.isIdentifier(node.property) &&
        t.isIdentifier((node.object as t.MemberExpression).object, {
          name: "process",
        }) &&
        t.isIdentifier((node.object as t.MemberExpression).property, {
          name: "env",
        })
      ) {
        const varName = node.property.name;
        if (!allowed.includes(varName)) {
          issues.push({
            type: "env",
            line: node.loc?.start.line || 0,
            message: `Access to process.env.${varName} detected`,
            severity: "medium",
            code: getLine(node, context),
          });
        }
      }
    }

    return issues;
  }
}
