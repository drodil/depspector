use lazy_static::lazy_static;
use regex::Regex;

use super::{FileAnalyzer, FileContext, Issue, Severity};

use regex::RegexSet;

lazy_static! {
    static ref AWS_ACCESS_KEY: Regex = Regex::new(
        r#"AKIA[0-9A-Z]{16}"#
    ).unwrap();

    static ref RSA_PRIVATE_KEY: Regex = Regex::new(
        r#"-----BEGIN RSA PRIVATE KEY-----"#
    ).unwrap();

    static ref PRIVATE_KEY: Regex = Regex::new(
        r#"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----"#
    ).unwrap();

    static ref STRIPE_SECRET: Regex = Regex::new(
        r#"sk_live_[0-9a-zA-Z]{24,}"#
    ).unwrap();

    static ref GITHUB_TOKEN: Regex = Regex::new(
        r#"gh[pousr]_[A-Za-z0-9_]{36,}"#
    ).unwrap();

    static ref GENERIC_API_KEY: Regex = Regex::new(
        r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-]{32,})['"]?"#
    ).unwrap();

    static ref NPM_TOKEN: Regex = Regex::new(
        r#"npm_[A-Za-z0-9]{36,}"#
    ).unwrap();

    static ref SLACK_TOKEN: Regex = Regex::new(
        r#"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}"#
    ).unwrap();

    static ref GOOGLE_API_KEY: Regex = Regex::new(
        r#"AIza[0-9A-Za-z\-_]{35}"#
    ).unwrap();

    static ref TWILIO_KEY: Regex = Regex::new(
        r#"SK[0-9a-fA-F]{32}"#
    ).unwrap();

    static ref SECRETS_SET: RegexSet = RegexSet::new([
        r#"AKIA[0-9A-Z]{16}"#, // 0: AWS
        r#"-----BEGIN RSA PRIVATE KEY-----"#, // 1: RSA
        r#"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----"#, // 2: Private Key
        r#"sk_live_[0-9a-zA-Z]{24,}"#, // 3: Stripe
        r#"gh[pousr]_[A-Za-z0-9_]{36,}"#, // 4: GitHub
        r#"npm_[A-Za-z0-9]{36,}"#, // 5: NPM
        r#"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}"#, // 6: Slack
        r#"AIza[0-9A-Za-z\-_]{35}"#, // 7: Google
        r#"SK[0-9a-fA-F]{32}"#, // 8: Twilio
        r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)"#, // 9: Generic API key pattern (context)
    ]).unwrap();
}

pub struct SecretsAnalyzer;

impl FileAnalyzer for SecretsAnalyzer {
  fn name(&self) -> &'static str {
    "secrets"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick regex check first - if no patterns match anywhere, skip AST parsing
    let matches = SECRETS_SET.matches(context.source);
    if !matches.matched_any() {
      return vec![];
    }

    let Some(ast) = context.parsed_ast else {
      return vec![];
    };

    let file_path = context.file_path.to_str().unwrap_or("");

    let mut issues = vec![]; // Check each string literal from the AST
    for string_lit in &ast.string_literals {
      let value = &string_lit.value;
      let line = string_lit.line.max(1);

      // Check each pattern
      if AWS_ACCESS_KEY.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential AWS Access Key ID found",
          Severity::Critical,
        );
      }

      if (RSA_PRIVATE_KEY.is_match(value) || PRIVATE_KEY.is_match(value))
        && has_matching_end_marker(context.source, string_lit.line.saturating_sub(1))
      {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential Private Key found",
          Severity::Critical,
        );
      }

      if STRIPE_SECRET.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential Stripe Secret Key found",
          Severity::Critical,
        );
      }

      if GITHUB_TOKEN.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential GitHub Token found",
          Severity::Critical,
        );
      }

      if NPM_TOKEN.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential npm Token found",
          Severity::Critical,
        );
      }

      if SLACK_TOKEN.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential Slack Token found",
          Severity::Critical,
        );
      }

      if GOOGLE_API_KEY.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential Google API Key found",
          Severity::High,
        );
      }

      if TWILIO_KEY.is_match(value) {
        add_issue(
          &mut issues,
          self.name(),
          file_path,
          context.package_name,
          line,
          value,
          "Potential Twilio API Key found",
          Severity::Critical,
        );
      }

      if value.len() >= 20 {
        let line_text = context.source.lines().nth(line.saturating_sub(1)).unwrap_or("");
        if GENERIC_API_KEY.is_match(line_text)
          && !AWS_ACCESS_KEY.is_match(value)
          && !STRIPE_SECRET.is_match(value)
          && !GITHUB_TOKEN.is_match(value)
        {
          add_issue(
            &mut issues,
            self.name(),
            file_path,
            context.package_name,
            line,
            value,
            "Potential hardcoded API key or secret found",
            Severity::High,
          );
        }
      }
    }

    issues
  }
}

#[allow(clippy::too_many_arguments)]
fn add_issue(
  issues: &mut Vec<Issue>,
  analyzer_name: &str,
  file_path: &str,
  package_name: Option<&str>,
  line: usize,
  value: &str,
  message: &str,
  severity: Severity,
) {
  let file_path_str = file_path.to_string();
  let mut issue = Issue::new(analyzer_name.to_string(), message.to_string(), severity, file_path_str)
    .with_line(line)
    .with_code(redact_secret(value));
  if let Some(pkg) = package_name {
    issue = issue.with_package_name(pkg);
  }
  issues.push(issue);
}

fn redact_secret(value: &str) -> String {
  if value.len() > 80 {
    format!("{}...[REDACTED]", &value[..40])
  } else {
    value.to_string()
  }
}

fn has_matching_end_marker(source: &str, begin_line: usize) -> bool {
  // Check if there's an END marker within reasonable distance (e.g., next 100 lines)
  let lines: Vec<&str> = source.lines().collect();
  let start = begin_line;
  let end = (begin_line + 100).min(lines.len());

  lines.iter().skip(start).take(end - start).any(|line| line.contains("-----END"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_aws_access_key() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::Critical);
    assert!(issues[0].message.contains("AWS"));
  }

  #[test]
  fn test_detects_private_key() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source =
      r#"const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";"#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("Private Key"));
  }

  #[test]
  fn test_detects_stripe_key() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const stripe = "sk_live_abcdefghijklmnopqrstuvwx";"#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("Stripe"));
  }

  #[test]
  fn test_detects_github_token() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const token = "ghp_123456789012345678901234567890123456";"#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("GitHub"));
  }

  #[test]
  fn test_detects_npm_token() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const token = "npm_123456789012345678901234567890123456";"#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("npm"));
  }

  #[test]
  fn test_detects_generic_api_key() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const apiKey = "abc123def456ghi789jkl012mno345pqr678";"#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("API key"));
  }

  #[test]
  fn test_ignores_safe_code() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
      const shortVar = "abc123";
      const publicKey = "pk_test_123";
    "#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 0);
  }

  #[test]
  fn test_ignores_comments() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.ts");

    let source = r#"
      /**
       * - clientSecret - Secret string used for token requests
       * - clientCertificate - PEM encoded private key (-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----)
       */
      const config = {};
    "#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: ast.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    // Comments are not parsed as string literals, so should be ignored
    assert_eq!(issues.len(), 0);
  }
}
