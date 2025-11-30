import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

export class EvalAnalyzer implements FileAnalyzerPlugin {
  name = "eval";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (t.isCallExpression(node)) {
      const callee = node.callee;

      if (t.isIdentifier(callee, { name: "eval" })) {
        issues.push({
          type: "eval",
          line: node.loc?.start.line || 0,
          message: "Usage of eval() detected",
          severity: "critical",
          code: getLine(node, context),
        });
      }
    }

    if (t.isNewExpression(node)) {
      if (t.isIdentifier(node.callee, { name: "Function" })) {
        issues.push({
          type: "eval",
          line: node.loc?.start.line || 0,
          message: "Usage of new Function() detected",
          severity: "medium",
          code: getLine(node, context),
        });
      }
    }

    return issues;
  }
}
