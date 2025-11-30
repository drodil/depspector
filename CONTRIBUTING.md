# Contributing to Depspector

Thank you for your interest in contributing to Depspector! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Quality](#code-quality)
- [Commit Guidelines](#commit-guidelines)
- [Testing](#testing)
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

### Building the Project

```bash
npm run build
```

This compiles TypeScript files from `src/` to `dist/`.

### Running During Development

```bash
# Build first
npm run build

# Then run with options
node dist/cli.js --verbose
node dist/cli.js --clear-cache
```

### Project Structure

```
src/
├── cli.ts              # Command-line interface
├── analyzer.ts         # Main analyzer orchestration
├── config.ts           # Configuration management
├── cache.ts            # Caching system
├── differ.ts           # Package diffing functionality
├── report.ts           # Report generation
├── registryUtil.ts     # NPM registry utilities
├── util.ts             # General utilities
└── analyzers/          # Individual analyzer plugins
    ├── base.ts         # Base analyzer interfaces
    ├── env.ts          # Environment variable detection
    ├── network.ts      # Network call detection
    ├── eval.ts         # Dynamic code execution detection
    ├── fs.ts           # File system access detection
    ├── obfuscation.ts  # Code obfuscation detection
    ├── typosquat.ts    # Typosquatting detection
    ├── cooldown.ts     # New package detection
    ├── dormant.ts      # Dormant package detection
    ├── dynamic.ts      # Dynamic loading detection
    └── reputation.ts   # Package reputation analysis
```

## Code Quality

We maintain high code quality standards using several tools:

### ESLint

ESLint is used to enforce code style and catch potential bugs.

```bash
# Check for linting errors
npm run lint

# Automatically fix linting errors
npm run lint:fix
```

Configuration: `eslint.config.js`

### Prettier

Prettier is used for consistent code formatting.

```bash
# Check code formatting
npm run prettier:check

# Automatically format code
npm run prettier:fix
```

Configuration: `.prettierrc` (if exists) or defaults in `package.json`

### TypeScript

We use TypeScript for type safety. Ensure your code:

- Has proper type annotations
- Passes TypeScript compilation without errors
- Uses interfaces for complex types

Configuration: `tsconfig.json`

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
- **style**: Code style changes (formatting, missing semicolons, etc.)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Changes to build process or auxiliary tools

### Examples

```bash
# Good commit messages
feat(analyzer): add support for dynamic import detection
fix(cache): clear all directories when using --clear-cache
docs(readme): update installation instructions
test(analyzer): add unit tests for env analyzer

# Bad commit messages (will be rejected)
update stuff
fix bug
WIP
```

### Scope

Common scopes include:

- `analyzer` - Main analyzer logic
- `cli` - Command-line interface
- `cache` - Caching system
- `config` - Configuration
- `differ` - Diffing functionality
- `report` - Reporting
- `test` - Testing infrastructure

Configuration: `commitlint.config.js`

## Testing

We use Jest for testing. All contributions should include appropriate tests.

### Running Tests

```bash
# Run all tests
npm test

# Run unit tests only
npm run test:unit

# Run end-to-end tests only
npm run test:e2e

# Run tests with coverage
npm run test:coverage
```

### Writing Tests

- Unit tests go in `tests/unit/`
- End-to-end tests go in `tests/e2e/`
- Test fixtures go in `tests/fixtures/`

Example unit test structure:

```typescript
import { MyAnalyzer } from "../../src/analyzers/myanalyzer";

describe("MyAnalyzer", () => {
  it("should detect suspicious pattern", () => {
    // Test implementation
  });
});
```

### Test Coverage

We aim for high test coverage. New features should include:

- Unit tests for individual components
- Integration tests for feature workflows
- Edge case handling

## Pull Request Process

1. **Before submitting:**
   - Ensure all tests pass: `npm test`
   - Run linting: `npm run lint:fix`
   - Run formatting: `npm run prettier:fix`
   - Update documentation if needed
   - Build succeeds: `npm run build`

2. **PR Description:**
   - Clearly describe what your PR does
   - Reference any related issues
   - Include screenshots for UI changes (if applicable)
   - List any breaking changes

3. **PR Title:**
   - Follow conventional commit format
   - Example: `feat(analyzer): add new malware detection pattern`

4. **Review Process:**
   - Maintain your PR by addressing review feedback
   - Keep your branch up to date with main
   - Squash commits if requested

5. **After Approval:**
   - Maintainers will merge your PR
   - Your contribution will be included in the next release

## Adding New Analyzers

To add a new analyzer:

1. Create a new file in `src/analyzers/` (e.g., `myanalyzer.ts`)
2. Implement either `FileAnalyzerPlugin` or `PackageAnalyzerPlugin` interface
3. Register the analyzer in `src/analyzer.ts`
4. Add configuration options to `src/config.ts` if needed
5. Add tests in `tests/unit/analyzers/`
6. Update documentation in README.md

Example analyzer structure:

```typescript
import { FileAnalyzerPlugin, AnalyzerContext } from "./base";
import { Issue } from "../analyzer";

export class MyAnalyzer implements FileAnalyzerPlugin {
  name = "myanalyzer";
  type = "file" as const;

  analyze(node: any, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];
    // Analysis logic here
    return issues;
  }
}
```

## Questions or Issues?

- Open an issue on GitHub for bugs or feature requests
- Start a discussion for questions or ideas
- Check existing issues before creating new ones

## License

By contributing to Depspector, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing! 🎉
