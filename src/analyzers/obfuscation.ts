import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

export class ObfuscationAnalyzer implements FileAnalyzerPlugin {
  name = "obfuscation";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    const obfuscationConfig = context.config.analyzers?.obfuscation;
    const minStringLength = obfuscationConfig?.minStringLength ?? 200;

    if (t.isStringLiteral(node)) {
      if (node.value.length >= minStringLength && !node.value.includes(" ")) {
        issues.push({
          type: "obfuscation",
          line: node.loc?.start.line || 0,
          message: "Suspiciously long string detected (potential obfuscation)",
          severity: "low",
          code: getLine(node, context).substring(0, 50) + "...",
        });
      }
    }

    return issues;
  }
}
