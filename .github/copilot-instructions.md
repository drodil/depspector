# GitHub Copilot Instructions for Depspector

This file provides guidance to GitHub Copilot when assisting with the Depspector project.

## Project Overview

Depspector is a security analysis tool for npm packages, written in **Rust** and distributed via npm using **napi-rs** for native Node.js bindings.

## Code Quality Standards

- Do not overuse comments. No need to comment every function or line. Focus on clear, self-explanatory code.
  If you do add comments, ensure they add value and explain the "why" rather than the "what".

### Rust Formatting

- **ALL Rust code must be formatted with `rustfmt`** before committing
- Run `cargo fmt` to format code automatically
- Check formatting with `cargo fmt -- --check`
- Follow the project's `rustfmt.toml` configuration

### Rust Linting

- **No Clippy warnings should exist** in any code
- Run `cargo clippy -- -D warnings` to check for issues
- Address all Clippy warnings and errors before considering code complete

### JavaScript/Config Formatting

- Use Prettier for JavaScript/JSON files
- Run `npm run prettier:fix` to format
- Run `npm run lint` for ESLint checks

### Rust Best Practices

- Use proper type annotations
- Prefer `Result<T, E>` over panics for error handling
- Use `thiserror` for custom error types
- Leverage Rust's ownership system for memory safety
- Ensure code passes `cargo build --release` without errors

## Testing Requirements

### Unit Tests

- **ALL new code must include unit tests**
- Tests should be in the same file using `#[cfg(test)]` modules
- Use `#[test]` attribute for test functions
- Group related tests in `mod tests { ... }`

### Test Coverage

- Aim for high test coverage (>80%)
- Test both success and failure cases
- Include edge cases and boundary conditions
- Run tests with `cargo test` before submitting

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something_specific() {
        // Arrange
        let input = "test";

        // Act
        let result = function_under_test(input);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_edge_case() {
        // Test implementation
    }
}
```

### E2E Tests

- E2E tests are located in `__tests__/` directory
- Tests use Vitest framework
- **IMPORTANT**: Before running E2E tests, you MUST build the NAPI binary:
  1. Run `npm run build` to compile and copy the native binary
  2. Then run `npm test` to execute all E2E tests
  3. Or run `npm test -- <pattern>` to run specific test files
- E2E tests invoke the CLI binary and verify output
- Test fixtures are in `__tests__/__fixtures__/`

### Running the CLI Locally

To run the tool locally using `node bin.js`:

1. First compile the NAPI binary with `npm run build:debug`
2. Then run `node bin.js [options]` to execute the CLI

## Analyzer Development

### Creating New Analyzers

When creating a new analyzer:

1. **Create the analyzer file:**
   - Add `src-rs/analyzers/<name>.rs`
   - Follow existing analyzer patterns

2. **Add to the registry:**
   - Add `pub mod <name>;` in `src-rs/analyzers/mod.rs`
   - Add analyzer call in `Analyzer::analyze_packages` method

3. **Configuration:**
   - **ALL analyzers MUST be configurable** - follow existing patterns
   - Add configuration struct in `src-rs/config.rs`
   - Support `enabled` field to allow disabling the analyzer
   - Use `Option<T>` with `.unwrap_or(default)` for optional config
   - Examples of configurable options:
     - Thresholds: `min_buffer_length`, `min_string_length`, `hours_since_publish`
     - Whitelists: `allowed_variables`, `allowed_hosts`, `whitelisted_users`
     - Additional items: `additional_dangerous_paths`

4. **Documentation:**
   - Update README.md with analyzer description
   - Add configuration examples
   - Document default values and behavior

5. **Testing:**
   - Add `#[cfg(test)]` module in analyzer file
   - Test default behavior
   - Test configuration options
   - Test edge cases

### Analyzer Code Patterns

```rust
use crate::config::Config;
use crate::report::Issue;

pub struct MyAnalyzer;

impl MyAnalyzer {
    pub fn analyze(content: &str, config: &Config) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Get configuration with defaults
        let threshold = config.analyzers
            .as_ref()
            .and_then(|a| a.myanalyzer.as_ref())
            .and_then(|c| c.threshold)
            .unwrap_or(100);

        // Analysis logic

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_issue() {
        let content = "suspicious code";
        let config = Config::default();
        let issues = MyAnalyzer::analyze(content, &config);
        assert!(!issues.is_empty());
    }
}
```

## Commit Standards

### Conventional Commits

- Use conventional commit format: `type(scope): subject`
- Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`
- Example: `feat(analyzer): add buffer detection with configurable threshold`

### Commit Validation

- Commits are validated with commitlint
- Must follow conventional commit specification
- Scope should reference the affected component

## Code Organization

### File Structure

```
src-rs/
├── lib.rs           # Library entry point, napi exports
├── config.rs        # Configuration structures
├── cache.rs         # Caching utilities
├── differ.rs        # Diff utilities
├── registry.rs      # npm registry interactions
├── report.rs        # Issue/Report types
├── util.rs          # Shared utilities
├── error.rs         # Error types
└── analyzers/
    ├── mod.rs       # Analyzer registry
    ├── buffer.rs    # Buffer analyzer
    ├── network.rs   # Network analyzer
    └── ...          # Other analyzers
```

### Constants

- Move reusable constants outside functions
- Use `UPPER_SNAKE_CASE` for constants
- Use `const` for compile-time constants
- Use `lazy_static!` or `once_cell` for runtime-initialized constants

### Imports

- Group imports: `std`, external crates, internal modules
- Use consistent import ordering
- Prefer explicit imports over glob imports

## Development Workflow

### Before Making Changes

1. Check existing code patterns
2. Review similar implementations
3. Understand the analyzer system
4. Review configuration patterns

### During Development

1. Write tests alongside code (TDD preferred)
2. Run `cargo check` frequently
3. Run `cargo clippy` regularly
4. Format with `cargo fmt`
5. Run `cargo test` to verify tests pass

### Before Committing

1. ✅ All tests pass (`cargo test`)
2. ✅ No Clippy warnings (`cargo clippy -- -D warnings`)
3. ✅ Code is formatted (`cargo fmt`)
4. ✅ Build succeeds (`cargo build --release`)
5. ✅ E2E tests pass (`npm run build && npm test`)
6. ✅ Documentation updated if needed (README.md for user-facing changes)
7. ✅ Commit message follows conventional format

**IMPORTANT**: Always update `README.md` when:

- Adding new CLI flags or options
- Adding or modifying analyzers
- Changing default behavior
- Adding new configuration options

## Common Patterns

### Configurable Thresholds

```rust
let threshold = config.analyzers
    .as_ref()
    .and_then(|a| a.myanalyzer.as_ref())
    .and_then(|c| c.threshold)
    .unwrap_or(DEFAULT_THRESHOLD);
```

### Issue Creation

```rust
issues.push(Issue {
    issue_type: "analyzer-name".to_string(),
    line: line_number,
    message: "Descriptive message".to_string(),
    severity: Severity::High,
    code: Some(code_snippet.to_string()),
});
```

### Whitelisting Pattern

```rust
let allowed_items: Vec<String> = config.analyzers
    .as_ref()
    .and_then(|a| a.myanalyzer.as_ref())
    .and_then(|c| c.allowed_items.clone())
    .unwrap_or_default();

if allowed_items.contains(&item) {
    return issues; // Skip whitelisted items
}
```

### Error Handling

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Failed to parse file: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AnalyzerError>;
```

## napi-rs Integration

### Exposing Functions to Node.js

```rust
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub fn analyze(path: String) -> Result<String> {
    // Implementation
    Ok("result".to_string())
}

#[napi(object)]
pub struct ScanResult {
    pub issues: Vec<Issue>,
    pub packages_scanned: u32,
}
```

## Performance Considerations

- Use `rayon` for parallel processing where beneficial
- Implement caching for expensive operations (registry lookups)
- Use `&str` instead of `String` when possible
- Consider memory usage for large codebases
- Use streaming for large file processing

## Security

- Never commit sensitive data
- Validate all external inputs
- Handle errors gracefully
- Follow secure coding practices
- Use safe Rust patterns (avoid `unsafe` unless necessary)

## Questions?

Refer to:

- `CONTRIBUTING.md` for detailed guidelines
- `README.md` for user documentation
- Existing analyzer implementations in `src-rs/analyzers/`
- napi-rs documentation: https://napi.rs
