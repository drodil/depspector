# Contributing to Depspector

Thank you for your interest in contributing to Depspector! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Building the Project](#building-the-project)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Commit Guidelines](#commit-guidelines)
- [Adding New Analyzers](#adding-new-analyzers)
- [Pull Request Process](#pull-request-process)

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/depspector.git
   cd depspector
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Requirements

- **Rust** (latest stable) - Install via [rustup](https://rustup.rs/)
- **Node.js** 18+ with npm
- **@napi-rs/cli** - Installed as a devDependency

### Project Structure

```
src-rs/                 # Rust source code
├── lib.rs              # Main entry point, napi exports, CLI
├── config.rs           # Configuration management
├── error.rs            # Error types (thiserror)
├── util.rs             # Utility functions
├── cache.rs            # Caching system
├── differ.rs           # Package diffing
├── registry.rs         # npm registry API client
├── report.rs           # Report generation
└── analyzers/          # Security analyzers
    ├── mod.rs          # Analyzer registry and traits
    ├── buffer.rs       # Buffer detection
    ├── cooldown.rs     # New package detection
    ├── cve.rs          # CVE detection
    ├── dormant.rs      # Dormant package detection
    ├── dynamic.rs      # Dynamic require detection
    ├── env.rs          # Environment variable detection
    ├── eval.rs         # Eval detection
    ├── fs.rs           # Filesystem access detection
    ├── metadata.rs     # Package metadata analysis
    ├── minified.rs     # Minified code detection
    ├── native.rs       # Native addon detection
    ├── network.rs      # Network call detection
    ├── obfuscation.rs  # Obfuscation detection
    ├── pollution.rs    # Prototype pollution detection
    ├── process.rs      # Process access detection
    ├── reputation.rs   # Package reputation analysis
    ├── scripts.rs      # Script hook detection
    ├── secrets.rs      # Secrets/credentials detection
    └── typosquat.rs    # Typosquatting detection

npm/                    # Platform-specific npm packages
├── darwin-arm64/       # macOS ARM64
├── darwin-x64/         # macOS x64
├── linux-x64-gnu/      # Linux x64 (glibc)
├── linux-x64-musl/     # Linux x64 (musl)
├── linux-arm64-gnu/    # Linux ARM64
└── win32-x64-msvc/     # Windows x64
```

## Building the Project

```bash
# Build Rust native binary (release)
npm run build

# Build Rust native binary (debug, faster compilation)
npm run build:debug

# Run locally
node bin.js --help
node bin.js --path ./node_modules

# Run Rust tests
cargo test

# Check Rust formatting
cargo fmt --check

# Run Rust linter
cargo clippy -- -D warnings
```

## Code Quality

### Rust Formatting

All Rust code must be formatted with `rustfmt`:

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Rust Linting

No Clippy warnings should exist:

```bash
cargo clippy -- -D warnings
```

### JavaScript/Config Files

ESLint and Prettier are used for JavaScript and configuration files:

```bash
# Check linting
npm run lint

# Fix linting issues
npm run lint:fix

# Check formatting
npm run prettier:check

# Fix formatting
npm run prettier:fix
```

## Testing

### Rust Unit Tests

All new Rust code must include unit tests in the same file:

```bash
# Run all Rust tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

### Test Structure

Tests should be in a `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Arrange
        let input = "test";

        // Act
        let result = my_function(input);

        // Assert
        assert!(result.is_ok());
    }
}
```

### JavaScript Binding Tests

```bash
npm test
```

## Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/) enforced by [commitlint](https://commitlint.js.org/).

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Code style changes (formatting)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Changes to build process or auxiliary tools

### Examples

```bash
# Good commit messages
feat(analyzer): add support for CVE detection
fix(cache): clear all directories when using --clear-cache
docs(readme): update installation instructions
test(network): add unit tests for network analyzer

# Bad commit messages (will be rejected)
update stuff
fix bug
WIP
```

### Scope

Common scopes include:

- `analyzer` - Analyzer logic
- `cli` - Command-line interface
- `cache` - Caching system
- `config` - Configuration
- `differ` - Diffing functionality
- `report` - Reporting
- `registry` - npm registry API

## Adding New Analyzers

### Step 1: Create the Analyzer File

Create `src-rs/analyzers/myanalyzer.rs`:

```rust
//! My Analyzer - Detects suspicious patterns
//!
//! This analyzer looks for [description].

use crate::config::Config;
use crate::report::{Issue, Severity};
use crate::util::generate_issue_id;

/// Default threshold value
const DEFAULT_THRESHOLD: usize = 100;

/// Analyze source code for suspicious patterns
pub fn analyze(
    content: &str,
    file_path: &str,
    config: &Config,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Get configuration with defaults
    let threshold = config.analyzers
        .as_ref()
        .and_then(|a| a.myanalyzer.as_ref())
        .and_then(|c| c.threshold)
        .unwrap_or(DEFAULT_THRESHOLD);

    // Analysis logic
    for (line_num, line) in content.lines().enumerate() {
        if line.contains("suspicious_pattern") {
            let id = generate_issue_id(
                "myanalyzer",
                file_path,
                line_num + 1,
                "Suspicious pattern detected",
            );

            issues.push(Issue {
                issue_type: "myanalyzer".to_string(),
                line: line_num + 1,
                message: "Suspicious pattern detected".to_string(),
                severity: Severity::High,
                code: Some(line.trim().to_string()),
                analyzer: Some("myanalyzer".to_string()),
                id: Some(id),
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_suspicious_pattern() {
        let content = "const x = suspicious_pattern();";
        let config = Config::default();

        let issues = analyze(content, "test.js", &config);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue_type, "myanalyzer");
    }

    #[test]
    fn test_clean_code_no_issues() {
        let content = "const x = normalFunction();";
        let config = Config::default();

        let issues = analyze(content, "test.js", &config);

        assert!(issues.is_empty());
    }
}
```

### Step 2: Register the Analyzer

Add to `src-rs/analyzers/mod.rs`:

```rust
pub mod myanalyzer;
```

And call it in the `analyze_packages` method.

### Step 3: Add Configuration (Optional)

Add to `src-rs/config.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct MyAnalyzerConfig {
    pub enabled: Option<bool>,
    pub threshold: Option<usize>,
    pub allowed_patterns: Option<Vec<String>>,
}
```

### Step 4: Update Documentation

- Update README.md with analyzer description
- Add configuration examples
- Document default values

## Pull Request Process

1. **Before submitting:**
   - Ensure all Rust tests pass: `cargo test`
   - Run Clippy: `cargo clippy -- -D warnings`
   - Run formatting: `cargo fmt`
   - Run linting: `npm run lint`
   - Build succeeds: `npm run build`

2. **PR Description:**
   - Clearly describe what your PR does
   - Reference any related issues
   - List any breaking changes

3. **PR Title:**
   - Follow conventional commit format
   - Example: `feat(analyzer): add CVE detection analyzer`

4. **Review Process:**
   - Address review feedback
   - Keep your branch up to date with main
   - Squash commits if requested

5. **After Approval:**
   - Maintainers will merge your PR
   - Your contribution will be included in the next release

## Cross-Platform Builds

The CI/CD pipeline builds native binaries for:

- macOS (x64, ARM64)
- Linux (x64 glibc, x64 musl, ARM64)
- Windows (x64)

Each platform has its own npm package that is listed as an `optionalDependency`. npm automatically downloads the correct binary for the user's platform.

## Questions or Issues?

- Open an issue on GitHub for bugs or feature requests
- Start a discussion for questions or ideas
- Check existing issues before creating new ones

## License

By contributing to Depspector, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing! 🎉
