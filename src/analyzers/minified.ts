import { Node } from "@babel/types";
import { Issue } from "../analyzer";
import { AnalyzerContext, FileAnalyzerPlugin } from "./base";

export class MinifiedAnalyzer implements FileAnalyzerPlugin {
  name = "minified";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    if (node.type === "Program") {
      const code = context.code;
      const lines = code.split("\n");

      const longLines = lines.filter((line) => line.length > 1000);
      if (longLines.length > 0) {
        issues.push({
          type: "minified",
          message: `File contains very long lines (${longLines[0].length} chars). It might be minified or obfuscated.`,
          severity: "low",
          line: 1,
        });
      }

      if (code.length > 500) {
        const whitespaceCount = (code.match(/\s/g) || []).length;
        const ratio = whitespaceCount / code.length;
        if (ratio < 0.05) {
          // Less than 5% whitespace
          issues.push({
            type: "minified",
            message:
              "File has very low whitespace ratio. It appears to be minified.",
            severity: "low",
            line: 1,
          });
        }
      }
    }

    return issues;
  }
}
