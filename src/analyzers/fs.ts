import * as t from "@babel/types";
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";
import { getLine } from "../util";

const DEFAULT_DANGEROUS_PATHS = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/hosts",
  "/etc/group",
  "/proc/self/environ",
  "/proc/self/cmdline",
  "/proc/self/cwd",
  ".ssh",
  "id_rsa",
  "id_ed25519",
  "authorized_keys",
  "known_hosts",
  ".npmrc",
  ".yarnrc",
  ".npmrc.yaml",
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".aws/credentials",
  ".aws/config",
  ".git/config",
  ".git/credentials",
  ".gitconfig",
  ".git-credentials",
  ".docker/config.json",
  ".kube/config",
  "kubeconfig",
  ".azure/credentials",
  ".config/gcloud",
  ".pgpass",
  ".my.cnf",
  ".redis/redis.conf",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".crt",
  ".csr",
  "private_key",
  "privatekey",
  ".bash_history",
  ".zsh_history",
  ".sh_history",
  "C:\\Windows\\System32\\config\\SAM",
  "C:\\Windows\\System32\\config\\SYSTEM",
  "NTUSER.DAT",
];

export class FsAnalyzer implements FileAnalyzerPlugin {
  name = "fs";
  type = "file" as const;
  requiresNetwork = false;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    const fsConfig = context.config.analyzers?.fs;
    const additionalDangerousPaths = fsConfig?.additionalDangerousPaths ?? [];

    const dangerousPaths = [
      ...DEFAULT_DANGEROUS_PATHS,
      ...additionalDangerousPaths,
    ];

    if (t.isCallExpression(node)) {
      const callee = node.callee;

      if (t.isMemberExpression(callee)) {
        const objectName = t.isIdentifier(callee.object)
          ? callee.object.name
          : "";
        const propertyName = t.isIdentifier(callee.property)
          ? callee.property.name
          : "";

        if (objectName === "fs" || objectName === "fs/promises") {
          if (node.arguments.length > 0) {
            const arg = node.arguments[0];
            if (t.isStringLiteral(arg)) {
              const path = arg.value;
              if (
                dangerousPaths.some((dangerPath) => path.includes(dangerPath))
              ) {
                issues.push({
                  type: "fs",
                  line: node.loc?.start.line || 0,
                  message: `Suspicious file access detected: ${path}`,
                  severity: "high",
                  code: getLine(node, context),
                });
              }
            }
          }

          if (
            [
              "writeFile",
              "writeFileSync",
              "appendFile",
              "appendFileSync",
            ].includes(propertyName)
          ) {
            issues.push({
              type: "fs",
              line: node.loc?.start.line || 0,
              message: `File write operation detected (${propertyName})`,
              severity: "medium",
              code: getLine(node, context),
            });
          }

          if (propertyName === "watch") {
            issues.push({
              type: "fs",
              line: node.loc?.start.line || 0,
              message: `File watch operation detected (fs.watch)`,
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
