import { AnalyzerContext } from "./analyzers/base";
import * as t from "@babel/types";

export function getLine(node: t.Node, context: AnalyzerContext): string {
  const lineNumber = node.loc?.start.line ?? 1;
  return context.code.split("\n")[lineNumber - 1].trim();
}
