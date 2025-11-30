import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

export class NetworkAnalyzer implements FileAnalyzerPlugin {
  name = "network";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];
    const config = context.config.analyzers?.network;

    if (t.isCallExpression(node)) {
      const callee = node.callee;

      if (t.isIdentifier(callee, { name: "fetch" })) {
        if (config?.allowedHosts && node.arguments.length > 0) {
          const arg = node.arguments[0];
          if (t.isStringLiteral(arg)) {
            const url = arg.value;
            if (config.allowedHosts.some((host) => url.includes(host))) {
              return [];
            }
          }
        }

        issues.push({
          type: "network",
          line: node.loc?.start.line || 0,
          message: "Network request detected (fetch)",
          severity: "medium",
          code: getLine(node, context),
        });
      }

      if (t.isMemberExpression(callee)) {
        const objectName = t.isIdentifier(callee.object)
          ? callee.object.name
          : "";
        const propertyName = t.isIdentifier(callee.property)
          ? callee.property.name
          : "";

        if (["http", "https", "axios", "got", "request"].includes(objectName)) {
          if (config?.allowedHosts && node.arguments.length > 0) {
            const arg = node.arguments[0];
            if (t.isStringLiteral(arg)) {
              const url = arg.value;
              if (config.allowedHosts.some((host) => url.includes(host))) {
                return [];
              }
            }
          }

          issues.push({
            type: "network",
            line: node.loc?.start.line || 0,
            message: `Network request detected (${objectName}.${propertyName})`,
            severity: "medium",
            code: getLine(node, context),
          });
        }
      }
    }

    return issues;
  }
}
