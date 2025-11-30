# GitHub Copilot Instructions for Depspector

This file provides guidance to GitHub Copilot when assisting with the Depspector project.

## Code Quality Standards

### Formatting

- **ALL code must be formatted with Prettier** before committing
- Run `npm run prettier:fix` to format code automatically
- Check formatting with `npm run prettier:check`
- Follow the project's Prettier configuration

### Linting

- **No ESLint errors should exist** in any code
- Run `npm run lint` to check for errors
- Use `npm run lint:fix` to automatically fix issues
- Address all linting warnings and errors before considering code complete

### TypeScript

- Use proper type annotations for all functions, parameters, and return types
- Avoid using `any` type unless absolutely necessary
- Leverage TypeScript's type system for better code safety
- Ensure code passes `npm run build` without errors

## Testing Requirements

### Unit Tests

- **ALL new code must include unit tests**
- Tests should be placed in `tests/unit/` following the source structure
- Use Jest for testing (`@jest/globals` imports)
- Import test utilities: `describe`, `it`, `expect`, `beforeEach`, `jest`
- Test files should end with `.test.ts`

### Test Coverage

- Aim for high test coverage (>80%)
- Test both success and failure cases
- Include edge cases and boundary conditions
- Run tests with `npm test` before submitting

### Test Structure

```typescript
import { describe, it, expect, beforeEach } from "@jest/globals";

describe("ComponentName", () => {
  beforeEach(() => {
    // Setup
  });

  it("should do something specific", () => {
    // Test implementation
  });
});
```

## Analyzer Development

### Creating New Analyzers

When creating a new analyzer:

1. **Implement the appropriate interface:**
   - `FileAnalyzerPlugin` for AST-based analysis
   - `PackageAnalyzerPlugin` for package-level analysis

2. **Add to the registry:**
   - Import in `src/analyzer.ts`
   - Add to the `allPlugins` array

3. **Configuration:**
   - **ALL analyzers MUST be configurable** - follow existing patterns
   - Add configuration interface in `src/config.ts`
   - Support `enabled` property to allow disabling the analyzer
   - Add analyzer-specific configuration options (thresholds, whitelists, etc.)
   - Use sensible defaults with the nullish coalescing operator (`??`)
   - Examples of configurable options:
     - Thresholds: `minBufferLength`, `minStringLength`, `hoursSincePublish`, `daysSincePreviousPublish`
     - Whitelists: `allowedVariables`, `allowedHosts`, `whitelistedUsers`
     - Additional items: `additionalDangerousPaths`

4. **Documentation:**
   - Update README.md with analyzer description
   - Add configuration examples
   - Document default values and behavior
   - Create a dedicated "Analyzer Configuration" section in README

5. **Testing:**
   - Create unit tests in `tests/unit/analyzers/`
   - Test default behavior
   - Test configuration options (especially custom thresholds/whitelists)
   - Test edge cases

### Analyzer Code Patterns

```typescript
export class MyAnalyzer implements FileAnalyzerPlugin {
  name = "myanalyzer";
  type = "file" as const;

  analyze(node: t.Node, context: AnalyzerContext): Issue[] {
    const issues: Issue[] = [];

    // Get configuration with defaults
    const config = context.config.analyzers?.myanalyzer;
    const threshold = config?.threshold ?? 100;

    // Analysis logic

    return issues;
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

- Analyzers in `src/analyzers/`
- Utilities in `src/` (e.g., `util.ts`, `registryUtil.ts`)
- Tests mirror source structure in `tests/`
- Configuration in `src/config.ts`

### Constants

- Move reusable constants outside classes
- Use UPPER_SNAKE_CASE for constants
- Example: `DEFAULT_DANGEROUS_PATHS`

### Imports

- Group imports logically (external, internal, types)
- Use consistent import ordering
- Prefer named imports over default imports

## Development Workflow

### Before Making Changes

1. Check existing code patterns
2. Review similar implementations
3. Understand the analyzer plugin system
4. Review configuration patterns

### During Development

1. Write tests alongside code (TDD preferred)
2. Run `npm run build` frequently
3. Check `npm run lint` regularly
4. Format with `npm run prettier:fix`
5. Run `npm test` to verify tests pass

### Before Committing

1. ✅ All tests pass (`npm test`)
2. ✅ No linting errors (`npm run lint`)
3. ✅ Code is formatted (`npm run prettier:fix`)
4. ✅ Build succeeds (`npm run build`)
5. ✅ Documentation updated if needed
6. ✅ Commit message follows conventional format

## Common Patterns

### Configurable Thresholds

```typescript
const config = context.config.analyzers?.myanalyzer;
const threshold = config?.myThreshold ?? DEFAULT_VALUE;
```

### Issue Creation

```typescript
issues.push({
  type: "analyzer-name",
  line: node.loc?.start.line || 0,
  message: "Descriptive message",
  severity: "critical" | "high" | "medium" | "low",
  code: getLine(node, context),
});
```

### Whitelisting Pattern

```typescript
const allowedItems = config?.allowedItems ?? [];
if (allowedItems.includes(item)) {
  return issues; // Skip whitelisted items
}
```

## Documentation

### README Updates

When adding features:

- Update Features section
- Add configuration examples
- Document default values
- Add to Analyzers table

### Code Comments

- Use JSDoc for public APIs
- Comment complex logic
- Explain "why" not "what"
- Keep comments up to date

## Performance Considerations

- Use parallel processing where possible
- Implement caching for expensive operations
- Avoid redundant AST traversals
- Consider memory usage for large codebases

## Security

- Never commit sensitive data
- Validate all external inputs
- Handle errors gracefully
- Follow secure coding practices

## Questions?

Refer to:

- `CONTRIBUTING.md` for detailed guidelines
- `README.md` for user documentation
- Existing analyzer implementations for patterns
- TypeScript interfaces in `src/analyzers/base.ts`
