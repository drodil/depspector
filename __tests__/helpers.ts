import { spawnSync } from "child_process";
import { join } from "path";

export function invokeCli(args: string[]): {
  exitCode: number;
  stdout: string;
  stderr: string;
} {
  let finalArgs = args.includes("--include-tests")
    ? args
    : [...args, "--include-tests"];

  if (!finalArgs.includes("--path")) {
    finalArgs = [...finalArgs, "--path", "node_modules"];
  }

  if (!finalArgs.includes("--report-level")) {
    finalArgs = [...finalArgs, "--report-level", "low"];
  }

  // Add verbose logging to surface internal debug output during tests
  if (!finalArgs.includes("-v") && !finalArgs.includes("--verbose")) {
    finalArgs = ["-v", ...finalArgs];
  }

  const result = spawnSync(
    "node",
    [join(__dirname, "..", "bin.js"), ...finalArgs],
    {
      encoding: "utf-8",
      timeout: 60000,
    }
  );

  // Optional debug: echo captured output to Vitest logs when enabled
  if (process.env.SHOW_CLI_OUTPUT === "1") {
    console.log("\n[invokeCli] args:", finalArgs.join(" "));
    console.log("[invokeCli] exit:", result.status ?? "(unknown)");
    if (result.stdout) {
      console.log("[invokeCli] stdout:\n" + result.stdout);
    }
    if (result.stderr) {
      console.log("[invokeCli] stderr:\n" + result.stderr);
    }
  }

  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

export const FIXTURES_DIR = join(__dirname, "__fixtures__");

export function getFixturePath(name: string): string {
  return join(FIXTURES_DIR, name);
}
