# Depspector

<p align="center">
  <img src="logo.png" alt="Depspector Logo" width="800"/>
</p>

**Depspector** is an advanced post-install security analysis tool for npm dependencies. It goes beyond simple CVE checks by performing deep static analysis and behavioral heuristic detection on your `node_modules`.

## Features

- **🕵️ Deep Static Analysis**: Detects suspicious code patterns across 19 specialized analyzers:
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
  - Version diffing to highlight code changes between package versions
  - Incremental scanning with `--only-new` flag
  - Cache management for faster subsequent scans
  - Detailed reporting with severity levels (critical/high/medium/low)
  - CI/CD friendly with configurable exit codes

## Installation

NPM

```bash
npm install -g @drodil/depspector
# OR
npm install --save-dev @drodil/depspector
```

YARN

```bash
yarn install --dev @drodil/depspector
```

## Usage

Run Depspector in your project root:

```bash
npx @drodil/depspector
```

### Examples

```bash
# Run with verbose output
npx @drodil/depspector --verbose

# Clear cache before scanning
npx @drodil/depspector --clear-cache

# Show only new issues
npx @drodil/depspector --only-new

# Fail fast on first high severity issue
npx @drodil/depspector --fail-fast

# Run in offline mode (skip network-dependent analyzers)
npx @drodil/depspector --offline

# Analyze a different project directory
npx @drodil/depspector --cwd /path/to/project
```

### Development Usage

If you're developing depspector, use these commands:

```bash
# Build and run
npm run build
node dist/cli.js [options]

# Or use the run script (without options)
npm run run
```

### Options

- `-p, --path <path>`: Path to `node_modules` (default: `./node_modules`).
- `-c, --config <path>`: Path to configuration file (default: `.depspectorrc`).
- `--cwd <path>`: Working directory where to run the analysis (default: `.`).
- `--no-diff`: Disable diffing against previous versions (faster).
- `--verbose`: Show detailed progress.
- `--no-cache`: Disable package result caching (forces fresh analysis even if unchanged).
- `--clear-cache`: Clear stored cache entries before scanning (use to force full regeneration while keeping caching enabled afterward).
- `--fail-fast`: Stop analysis immediately when the first issue at or above the configured `exitWithFailureOnLevel` is found (useful for CI/CD to fail quickly).
- `--only-new`: Show only new issues found in this scan, excluding issues from cached packages (useful for incremental analysis).
- `--offline`: Disable analyzers that require network access (CVE, cooldown, dormant, reputation). Useful for environments without internet access or to speed up scans.
- `--ignore-issue <id...>`: Ignore specific issues by their ID (can be specified multiple times). Issue IDs are displayed in brackets after each finding.

## Performance

Depspector includes several optimizations for faster scanning:

- **Package Caching**: Caches both the fact a package was scanned and its findings. If a package's `package.json` is unchanged, its previous results are reused in the report (not silently dropped) and the code is not re-parsed.
- **Parallel Analysis**: Package-level analyzers and file-level analyzers run in parallel to maximize performance.
- **Configurable Cache Directory**: Use `cacheDir` in configuration to control where cache files are stored (useful for CI environments).

The first scan may be slow as it goes through all package dependencies.

To force a fresh scan of everything, either clear the cache directory or point `cacheDir` to a clean temporary location before running.

You can also use the CLI flags:

- `--clear-cache` to wipe existing cached entries before the scan starts.
- `--no-cache` to skip both reading and writing cache data for that run.

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
      "allowedVariables": ["NODE_ENV", "CI"]
    },
    "fs": {
      "enabled": true
    }
  },
  "exclude": ["internal-package"],
  "ignoreIssues": ["a1b2c3d4e5f6", "9f8e7d6c5b4a"],
  "exitWithFailureOnLevel": "high",
  "reportLevel": "medium"
}
```

### Configuration Options

| Option                   | Type                                                 | Default         | Description                                                                                    |
| ------------------------ | ---------------------------------------------------- | --------------- | ---------------------------------------------------------------------------------------------- |
| `analyzers`              | Object                                               | All enabled     | Configure individual analyzers (see [Analyzers](#analyzers) table).                            |
| `exclude`                | Array\<string\>                                      | `[]`            | Package names to exclude from scanning.                                                        |
| `ignoreIssues`           | Array\<string\>                                      | `[]`            | Issue IDs to ignore. Issue IDs are displayed in brackets after each finding in the report.     |
| `exitWithFailureOnLevel` | `"critical" \| "high" \| "medium" \| "low" \| "off"` | `"high"`        | Exit with code 1 if issues at this severity level or higher are found. Use `"off"` to disable. |
| `reportLevel`            | `"critical" \| "high" \| "medium" \| "low"`          | `null`          | Only report issues at this severity level or higher. If not set, all issues are reported.      |
| `failFast`               | boolean                                              | `false`         | Stop analysis immediately when first issue at or above `exitWithFailureOnLevel` is found.      |
| `cacheDir`               | string                                               | System temp dir | Directory to cache downloaded packages for diffing. Defaults to OS temp directory.             |
| `npm`                    | Object                                               | `{}`            | NPM registry configuration (see below).                                                        |

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
[MEDIUM] Suspicious network request detected (Line 42) [ID: a1b2c3d4e5f6]
```

### Ignoring via Configuration

Add issue IDs to your `.depspectorrc` file:

```json
{
  "ignoreIssues": ["a1b2c3d4e5f6", "9f8e7d6c5b4a"]
}
```

### Ignoring via CLI

You can also ignore issues temporarily using the `--ignore-issue` flag:

```bash
# Ignore a single issue
npx depspector --ignore-issue a1b2c3d4e5f6

# Ignore multiple issues
npx depspector --ignore-issue a1b2c3d4e5f6 --ignore-issue 9f8e7d6c5b4a
```

The CLI flag can be combined with configuration file settings. Both will be merged together.

## Analyzers

| Analyzer      | Description                                                                                            |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| `cve`         | Checks packages against OSV.dev database for known CVEs and security advisories. Configurable timeout. |
| `env`         | Detects access to environment variables (`process.env`). Supports `allowedVariables` whitelist.        |
| `network`     | Detects network requests. Supports `allowedHosts` whitelist.                                           |
| `eval`        | Flags `eval()` and `new Function()` usage.                                                             |
| `obfuscation` | Detects suspiciously long strings (potential obfuscation). Configurable `minStringLength`.             |
| `fs`          | Detects access to sensitive paths. Supports `additionalDangerousPaths`.                                |
| `typosquat`   | Identifies packages with names similar to popular libraries.                                           |
| `cooldown`    | Flags newly published packages. Configurable `hoursSincePublish`.                                      |
| `dormant`     | Alerts on packages updated after long inactivity. Configurable `daysSincePreviousPublish`.             |
| `dynamic`     | Detects `vm.runInContext()` and dynamic require patterns.                                              |
| `buffer`      | Flags suspicious `Buffer.from()` usage. Configurable `minBufferLength`.                                |
| `reputation`  | Checks maintainer count and publisher trustworthiness. Supports `whitelistedUsers`.                    |
| `scripts`     | Flags suspicious lifecycle scripts (install, postinstall, preinstall).                                 |
| `process`     | Detects child process spawning and low-level spawn calls.                                              |
| `native`      | Alerts on packages with native bindings.                                                               |
| `secrets`     | Identifies hardcoded credentials (AWS keys, private keys, API tokens).                                 |
| `metadata`    | Flags collection of system information (`os.userInfo()`, network interfaces).                          |
| `pollution`   | Detects prototype pollution attempts.                                                                  |
| `minified`    | Identifies minified or obfuscated code.                                                                |

### CVE Analyzer Configuration

The `cve` analyzer queries the [OSV.dev](https://osv.dev) database for known vulnerabilities affecting your dependencies. It maps CVE severity scores to Depspector's severity levels.

**Default CVSS Score Thresholds:**

- **Critical**: CVSS score ≥ 9.0
- **High**: CVSS score ≥ 7.0
- **Medium**: CVSS score ≥ 4.0
- **Low**: CVSS score < 4.0

You can customize these thresholds to match your organization's security policies:

```json
{
  "analyzers": {
    "cve": {
      "enabled": true,
      "timeout": 5000,
      "criticalThreshold": 8.0,
      "highThreshold": 6.0,
      "mediumThreshold": 4.0
    }
  }
}
```

| Property            | Type    | Default | Description                                        |
| ------------------- | ------- | ------- | -------------------------------------------------- |
| `enabled`           | boolean | `true`  | Enable/disable CVE checking.                       |
| `timeout`           | number  | `5000`  | Timeout in milliseconds for OSV.dev API requests.  |
| `criticalThreshold` | number  | `9.0`   | Minimum CVSS score to classify as critical (0-10). |
| `highThreshold`     | number  | `7.0`   | Minimum CVSS score to classify as high (0-10).     |
| `mediumThreshold`   | number  | `4.0`   | Minimum CVSS score to classify as medium (0-10).   |

| Property  | Type    | Default | Description                                              |
| --------- | ------- | ------- | -------------------------------------------------------- |
| `enabled` | boolean | `true`  | Enable/disable CVE scanning.                             |
| `timeout` | number  | `5000`  | Request timeout in milliseconds for OSV.dev API queries. |

**Note**: CVE scanning requires network access to `api.osv.dev`. Queries are made per package version and failures are silently ignored to avoid blocking analysis on network issues.

### Env Analyzer Configuration

You can whitelist specific environment variables to suppress findings when they are accessed intentionally (e.g., `NODE_ENV`, `CI`).

```json
{
  "analyzers": {
    "env": {
      "allowedVariables": ["NODE_ENV", "CI", "PUBLIC_API_URL"]
    }
  }
}
```

Any access to `process.env.<VAR>` where `<VAR>` is in `allowedVariables` will be ignored. Bare `process.env` access and non-whitelisted variables will still be reported.

### Fs Analyzer Configuration

The `fs` analyzer detects suspicious file system access. By default, it checks for sensitive paths like `/etc/passwd`, `.ssh`, `.npmrc`, `/proc/self/environ`, and lock files. You can add additional paths to monitor:

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

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for more information.

## License

MIT
