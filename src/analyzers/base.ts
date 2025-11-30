import { Node } from "@babel/types";
import { Issue } from "../analyzer";
import { DepspectorConfig } from "../config";

export interface AnalyzerContext {
  file: string;
  code: string;
  config: DepspectorConfig;
}

export interface PackageContext {
  name: string;
  version: string;
  path: string;
  config: DepspectorConfig;
  packageJson: any;
}

export interface AnalyzerPlugin {
  name: string;
  type: "file" | "package";
  requiresNetwork: boolean;
}

export interface FileAnalyzerPlugin extends AnalyzerPlugin {
  type: "file";
  analyze(node: Node, context: AnalyzerContext): Issue[];
}

export interface PackageAnalyzerPlugin extends AnalyzerPlugin {
  type: "package";
  analyze(context: PackageContext): Promise<Issue[]> | Issue[];
}
