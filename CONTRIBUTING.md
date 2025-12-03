# Contributing to Depspector

Thank you for your interest in contributing to Depspector! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Building the Project](#building-the-project)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Commit Guidelines](#commit-guidelines)
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
