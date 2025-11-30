#!/usr/bin/env node
import { Command } from "commander";
import glob from "glob";
import path from "path";
import fs from "fs";
import ora from "ora";
import chalk from "chalk";
import { Analyzer, AnalysisResult } from "./analyzer";
import { Differ, DiffResult } from "./differ";
import { Reporter } from "./report";
import { loadConfig } from "./config";
import { PackageCache } from "./cache";

const program = new Command();

const packageJsonPath = path.join(__dirname, "..", "package.json");
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
const version = packageJson.version;

program
  .version(version)
  .description("Post-install security analysis tool for npm dependencies")
  .option("-p, --path <path>", "Path to node_modules", "./node_modules")
  .option("-c, --config <path>", "Path to configuration file")
  .option("--cwd <path>", "Working directory where to run the analysis", ".")
  .option("--no-diff", "Disable diffing against previous version")
  .option("--verbose", "Show verbose output")
  .option("--no-cache", "Disable package result caching")
  .option("--clear-cache", "Clear cache before running scan")
  .option("--fail-fast", "Stop analysis on first issue at failure level")
  .option("--only-new", "Show only new issues, exclude cached results")
  .option("--offline", "Disable analyzers that require network access")
  .option(
    "--ignore-issue <id...>",
    "Issue IDs to ignore (can be specified multiple times)",
  )
  .action(async (options) => {
    const startTime = Date.now();
    const spinner = ora("Initializing...").start();

    const workingDir = path.resolve(options.cwd);
    if (!fs.existsSync(workingDir)) {
      spinner.fail(`Working directory not found at ${workingDir}`);
      process.exit(1);
    }
    process.chdir(workingDir);

    const config = loadConfig(options.config);
    const failFast = options.failFast || config.failFast || false;
    const onlyNew = options.onlyNew || false;
    const offline = options.offline || false;

    const ignoreIssues = [
      ...(config.ignoreIssues || []),
      ...(options.ignoreIssue || []),
    ];

    const analyzer = new Analyzer(config, offline);
    const differ = new Differ(config);
    const reporter = new Reporter();
    const cacheDir =
      config.cacheDir || path.join(require("os").tmpdir(), "depspector-cache");
    const cachingEnabled = !options.noCache;
    const packageCache = cachingEnabled ? new PackageCache(cacheDir) : null;

    if (packageCache && options.clearCache) {
      spinner.text = "Clearing cache...";
      packageCache.clearAll();
      if (options.verbose) spinner.text = "Cache cleared.";
    }

    const nodeModulesPath = path.resolve(options.path);

    if (!fs.existsSync(nodeModulesPath)) {
      spinner.fail(`node_modules not found at ${nodeModulesPath}`);
      process.exit(1);
    }

    spinner.text = "Scanning dependencies (including transitive)...";

    const ignorePatterns = [
      "**/.bin/**",
      "**/test/**",
      "**/tests/**",
      "**/__tests__/**",
      "**/*.test.js",
      "**/*.test.ts",
      "**/example/**",
      "**/examples/**",
      "**/dist/**/package.json",
      "**/build/**/package.json",
      ...(config.exclude || []).map((e) => `**/${e}/**`),
    ];

    const packageJsonFiles = glob.sync("**/package.json", {
      cwd: nodeModulesPath,
      ignore: ignorePatterns,
      follow: true,
    });

    const results: AnalysisResult[] = [];
    const diffs: DiffResult[] = [];

    for (const pkgJsonFile of packageJsonFiles) {
      const pkgDir = path.dirname(path.join(nodeModulesPath, pkgJsonFile));

      try {
        const pkgJson = JSON.parse(
          fs.readFileSync(path.join(nodeModulesPath, pkgJsonFile), "utf-8"),
        );

        if (!pkgJson.name || !pkgJson.version) continue;

        if (config.exclude && config.exclude.includes(pkgJson.name)) continue;

        if (
          packageCache &&
          !packageCache.hasChanged(pkgJson.name, pkgJson.version, pkgDir)
        ) {
          const cachedResults = packageCache.getResults(
            pkgJson.name,
            pkgJson.version,
          );
          if (cachedResults !== null) {
            if (cachedResults.length > 0) {
              const markedResults = cachedResults.map((r) => {
                const filteredIssues = r.issues.filter((issue) => {
                  if (!issue.analyzer) return true;
                  if (!analyzer.isAnalyzerEnabled(issue.analyzer)) return false;
                  if (issue.id && ignoreIssues.includes(issue.id)) return false;
                  return true;
                });
                return {
                  ...r,
                  issues: filteredIssues,
                  isFromCache: true,
                };
              });
              const nonEmptyResults = markedResults.filter(
                (r) => r.issues.length > 0,
              );
              if (nonEmptyResults.length > 0) {
                results.push(...nonEmptyResults);
              }
              if (options.verbose)
                spinner.text = `Using cached results for ${pkgJson.name}@${pkgJson.version}...`;
            } else {
              if (options.verbose)
                spinner.text = `Skipping ${pkgJson.name}@${pkgJson.version} (no issues cached)...`;
            }
            continue;
          }
        }

        if (options.verbose)
          spinner.text = `Analyzing ${pkgJson.name}@${pkgJson.version}...`;

        const pkgResult = await analyzer.analyzePackage({
          name: pkgJson.name,
          version: pkgJson.version,
          path: pkgDir,
          packageJson: pkgJson,
        });

        const jsFiles = glob.sync("**/*.{js,mjs,ts}", {
          cwd: pkgDir,
          ignore: [
            "node_modules/**",
            "test/**",
            "tests/**",
            "__tests__/**",
            "**/*.test.js",
            "**/*.test.ts",
            "**/*.d.ts",
            "**/*.min.js",
          ],
        });

        let packageHasIssues = pkgResult.issues.length > 0;
        const packageResults: AnalysisResult[] = [];

        const fileResults = await Promise.all(
          jsFiles.map((file) => {
            const filePath = path.join(pkgDir, file);
            return analyzer.analyzeFile(filePath);
          }),
        );

        for (const result of fileResults) {
          if (result.issues.length > 0) {
            packageResults.push(result);
            packageHasIssues = true;
          }
        }

        const allPackageResults: AnalysisResult[] = [];
        if (pkgResult.issues.length > 0) allPackageResults.push(pkgResult);
        if (packageResults.length > 0)
          allPackageResults.push(...packageResults);

        const filteredResults = allPackageResults
          .map((r) => ({
            ...r,
            issues: r.issues.filter(
              (issue) => !issue.id || !ignoreIssues.includes(issue.id),
            ),
          }))
          .filter((r) => r.issues.length > 0);

        if (filteredResults.length > 0) {
          results.push(...filteredResults);
        }

        if (packageHasIssues && options.diff) {
          spinner.text = `Verifying changes for ${pkgJson.name}...`;
          try {
            const packageDiffs = await differ.diffPackage(
              pkgJson.name,
              pkgJson.version,
              pkgDir,
            );
            diffs.push(...packageDiffs);
          } catch (e) {
            if (options.verbose) console.error(e);
          }
        }

        if (packageCache) {
          packageCache.updateEntry(
            pkgJson.name,
            pkgJson.version,
            pkgDir,
            allPackageResults,
          );
        }

        if (failFast && packageHasIssues) {
          const exitLevel = config.exitWithFailureOnLevel ?? "high";
          if (
            exitLevel !== "off" &&
            reporter.hasIssuesAtLevel(results, exitLevel)
          ) {
            spinner.stop();
            reporter.printReport(results, diffs, config.reportLevel, onlyNew);
            const endTime = Date.now();
            const durationInSeconds = ((endTime - startTime) / 1000).toFixed(2);
            console.log(`\nDone in ${durationInSeconds} seconds`);
            console.log(
              chalk.red("\nAnalysis stopped early due to --fail-fast"),
            );
            process.exit(1);
          }
        }
      } catch (e) {
        console.warn(`Failed to parse ${pkgJsonFile}: ${e}`);
      }
    }

    spinner.stop();
    reporter.printReport(results, diffs, config.reportLevel, onlyNew);

    const endTime = Date.now();
    const durationInSeconds = ((endTime - startTime) / 1000).toFixed(2);
    console.log(`\nDone in ${durationInSeconds} seconds`);

    const exitLevel = config.exitWithFailureOnLevel ?? "high";
    if (exitLevel !== "off" && reporter.hasIssuesAtLevel(results, exitLevel)) {
      process.exit(1);
    }
    process.exit(0);
  });

program.parse(process.argv);
