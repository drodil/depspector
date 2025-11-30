import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

export class BufferAnalyzer implements FileAnalyzerPlugin {
  name = "buffer";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    const bufferConfig = context.config.analyzers?.buffer;
    const minBufferLength = bufferConfig?.minBufferLength ?? 50;

    if (t.isCallExpression(node)) {
      if (
        t.isMemberExpression(node.callee) &&
        t.isIdentifier(node.callee.object, { name: "Buffer" }) &&
        t.isIdentifier(node.callee.property, { name: "from" })
      ) {
        if (node.arguments.length > 0 && t.isStringLiteral(node.arguments[0])) {
          const arg = node.arguments[0];
          if (arg.value.length > minBufferLength) {
            issues.push({
              type: "buffer",
              line: node.loc?.start.line || 0,
              message: `Suspicious Buffer.from() usage with long string (potential payload decoding)`,
              severity: "medium",
              code: getLine(node, context),
            });
          }
        }
      }
    }

    return issues;
  }
}
