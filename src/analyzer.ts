import fs from "fs";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";
import {
  AnalyzerPlugin,
  AnalyzerContext,
  FileAnalyzerPlugin,
  PackageAnalyzerPlugin,
  PackageContext,
} from "./analyzers/base";
import { EnvAnalyzer } from "./analyzers/env";
import { NetworkAnalyzer } from "./analyzers/network";
import { EvalAnalyzer } from "./analyzers/eval";
import { ObfuscationAnalyzer } from "./analyzers/obfuscation";
import { FsAnalyzer } from "./analyzers/fs";
import { TyposquatAnalyzer } from "./analyzers/typosquat";
import { CooldownAnalyzer } from "./analyzers/cooldown";
import { DormantAnalyzer } from "./analyzers/dormant";
import { DynamicAnalyzer } from "./analyzers/dynamic";
import { BufferAnalyzer } from "./analyzers/buffer";
import { ReputationAnalyzer } from "./analyzers/reputation";
import { ScriptsAnalyzer } from "./analyzers/scripts";
import { ProcessAnalyzer } from "./analyzers/process";
import { NativeAnalyzer } from "./analyzers/native";
import { SecretsAnalyzer } from "./analyzers/secrets";
import { MetadataAnalyzer } from "./analyzers/metadata";
import { PollutionAnalyzer } from "./analyzers/pollution";
import { MinifiedAnalyzer } from "./analyzers/minified";
import { CVEAnalyzer } from "./analyzers/cve";
import { DepspectorConfig } from "./config";
import crypto from "crypto";

function generateIssueId(issue: Issue, fileOrPackage: string): string {
  const data = `${fileOrPackage}:${issue.analyzer || issue.type}:${issue.line || "pkg"}:${issue.message}`;
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex")
    .substring(0, 12);
}

export interface AnalysisResult {
  file?: string;
  package?: string;
  issues: Issue[];
  isFromCache?: boolean;
  analyzers?: string[];
}

export interface Issue {
  type: string;
  line?: number;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  code?: string;
  analyzer?: string;
  id?: string;
}

export class Analyzer {
  private filePlugins: FileAnalyzerPlugin[];
  private packagePlugins: PackageAnalyzerPlugin[];
  private config: DepspectorConfig;
  private offline: boolean;

  constructor(config: DepspectorConfig = {}, offline: boolean = false) {
    this.config = config;
    this.offline = offline;

    // Initialize plugins
    const allPlugins: AnalyzerPlugin[] = [
      new EnvAnalyzer(),
      new NetworkAnalyzer(),
      new EvalAnalyzer(),
      new ObfuscationAnalyzer(),
      new FsAnalyzer(),
      new TyposquatAnalyzer(),
      new CooldownAnalyzer(),
      new DormantAnalyzer(),
      new DynamicAnalyzer(),
      new BufferAnalyzer(),
      new ReputationAnalyzer(),
      new ScriptsAnalyzer(),
      new ProcessAnalyzer(),
      new NativeAnalyzer(),
      new SecretsAnalyzer(),
      new MetadataAnalyzer(),
      new PollutionAnalyzer(),
      new MinifiedAnalyzer(),
      new CVEAnalyzer(),
    ];

    const filteredPlugins = offline
      ? allPlugins.filter((p) => !p.requiresNetwork)
      : allPlugins;

    this.filePlugins = filteredPlugins.filter(
      (p) => p.type === "file",
    ) as FileAnalyzerPlugin[];
    this.packagePlugins = filteredPlugins.filter(
      (p) => p.type === "package",
    ) as PackageAnalyzerPlugin[];
  }

  private isPluginEnabled(name: string): boolean {
    const pluginConfig = this.config.analyzers?.[name];
    return pluginConfig?.enabled !== false;
  }

  public isAnalyzerEnabled(name: string): boolean {
    const allEnabledPlugins = [
      ...this.filePlugins,
      ...this.packagePlugins,
    ].filter((p) => this.isPluginEnabled(p.name));
    return allEnabledPlugins.some((p) => p.name === name);
  }

  analyzeFile(filePath: string, code?: string): AnalysisResult {
    const content = code || fs.readFileSync(filePath, "utf-8");
    const issues: Issue[] = [];
    const enabledAnalyzers: string[] = [];

    const context: AnalyzerContext = {
      file: filePath,
      code: content,
      config: this.config,
    };

    try {
      const ast = parse(content, {
        sourceType: "unambiguous",
        plugins: ["typescript", "jsx"],
      });

      traverse(ast, {
        enter: (path) => {
          for (const plugin of this.filePlugins) {
            if (this.isPluginEnabled(plugin.name)) {
              if (!enabledAnalyzers.includes(plugin.name)) {
                enabledAnalyzers.push(plugin.name);
              }
              const pluginIssues = plugin.analyze(path.node, context);
              // Add analyzer name to each issue
              pluginIssues.forEach((issue) => {
                issue.analyzer = plugin.name;
              });
              issues.push(...pluginIssues);
            }
          }
        },
      });
    } catch {
      // Ignore parse errors
    }

    const uniqueIssues = issues.filter(
      (issue, index, self) =>
        index ===
        self.findIndex(
          (i) =>
            i.type === issue.type &&
            i.line === issue.line &&
            i.message === issue.message,
        ),
    );

    uniqueIssues.forEach((issue) => {
      issue.id = generateIssueId(issue, filePath);
    });

    return {
      file: filePath,
      issues: uniqueIssues,
      analyzers: enabledAnalyzers,
    };
  }

  async analyzePackage(pkgInfo: {
    name: string;
    version: string;
    path: string;
    packageJson: any;
  }): Promise<AnalysisResult> {
    const issues: Issue[] = [];
    const context: PackageContext = {
      ...pkgInfo,
      config: this.config,
    };

    const enabledPlugins = this.packagePlugins.filter((plugin) =>
      this.isPluginEnabled(plugin.name),
    );

    const pluginResults = await Promise.all(
      enabledPlugins.map(async (plugin) => ({
        name: plugin.name,
        issues: await plugin.analyze(context),
      })),
    );

    pluginResults.forEach((result) => {
      // Add analyzer name to each issue
      result.issues.forEach((issue) => {
        issue.analyzer = result.name;
        issue.id = generateIssueId(issue, `${pkgInfo.name}@${pkgInfo.version}`);
      });
      issues.push(...result.issues);
    });

    return {
      package: `${pkgInfo.name}@${pkgInfo.version}`,
      issues,
      analyzers: enabledPlugins.map((p) => p.name),
    };
  }
}
