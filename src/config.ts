import fs from "fs";
import path from "path";

export interface AnalyzerConfig {
  enabled?: boolean;
  [key: string]: any;
}

export interface ReputationConfig extends AnalyzerConfig {
  whitelistedUsers?: string[];
}

export interface DepspectorConfig {
  analyzers?: {
    env?: AnalyzerConfig & { allowedVariables?: string[] };
    network?: AnalyzerConfig & { allowedHosts?: string[] };
    eval?: AnalyzerConfig;
    obfuscation?: AnalyzerConfig & { minStringLength?: number };
    fs?: AnalyzerConfig & { additionalDangerousPaths?: string[] };
    typosquat?: AnalyzerConfig;
    cooldown?: AnalyzerConfig & { hoursSincePublish?: number };
    dormant?: AnalyzerConfig & { daysSincePreviousPublish?: number };
    dynamic?: AnalyzerConfig;
    buffer?: AnalyzerConfig & { minBufferLength?: number };
    reputation?: ReputationConfig;
    scripts?: AnalyzerConfig;
    process?: AnalyzerConfig;
    native?: AnalyzerConfig;
    secrets?: AnalyzerConfig;
    metadata?: AnalyzerConfig;
    pollution?: AnalyzerConfig;
    minified?: AnalyzerConfig;
    cve?: AnalyzerConfig & {
      timeout?: number;
      criticalThreshold?: number;
      highThreshold?: number;
      mediumThreshold?: number;
    };
    [key: string]: AnalyzerConfig | undefined;
  };
  exclude?: string[];
  ignoreIssues?: string[];
  exitWithFailureOnLevel?: "critical" | "high" | "medium" | "low" | "off";
  reportLevel?: "critical" | "high" | "medium" | "low";
  failFast?: boolean;
  cacheDir?: string;
  npm?: {
    registry?: string;
    token?: string;
    username?: string;
    password?: string;
  };
}

export function loadConfig(configPath?: string): DepspectorConfig {
  const finalPath = configPath
    ? path.resolve(configPath)
    : path.join(process.cwd(), ".depspectorrc");

  if (fs.existsSync(finalPath)) {
    try {
      return JSON.parse(fs.readFileSync(finalPath, "utf-8"));
    } catch (e) {
      console.error(`Failed to parse config at ${finalPath}`, e);
    }
  }
  return {};
}
