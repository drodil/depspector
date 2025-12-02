use lazy_static::lazy_static;
use regex::Regex;

use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;

lazy_static! {
    static ref AWS_ACCESS_KEY: Regex = Regex::new(
        r#"AKIA[0-9A-Z]{16}"#
    ).unwrap();

    static ref AWS_SECRET_KEY: Regex = Regex::new(
        r#"[A-Za-z0-9/+=]{40}"#
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
        r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#
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
}

pub struct SecretsAnalyzer;

impl FileAnalyzer for SecretsAnalyzer {
  fn name(&self) -> &'static str {
    "secrets"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    for (line_num, line) in context.source.lines().enumerate() {
      if AWS_ACCESS_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential AWS Access Key ID found",
          Severity::Critical,
        ));
      }

      if RSA_PRIVATE_KEY.is_match(line) || PRIVATE_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Private Key found",
          Severity::Critical,
        ));
      }

      if STRIPE_SECRET.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Stripe Secret Key found",
          Severity::Critical,
        ));
      }

      if GITHUB_TOKEN.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential GitHub Token found",
          Severity::Critical,
        ));
      }

      if NPM_TOKEN.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential npm Token found",
          Severity::Critical,
        ));
      }

      if SLACK_TOKEN.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Slack Token found",
          Severity::Critical,
        ));
      }

      if GOOGLE_API_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Google API Key found",
          Severity::High,
        ));
      }

      if TWILIO_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Twilio API Key found",
          Severity::Critical,
        ));
      }

      if GENERIC_API_KEY.is_match(line)
        && !AWS_ACCESS_KEY.is_match(line)
        && !STRIPE_SECRET.is_match(line)
        && !GITHUB_TOKEN.is_match(line)
      {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential hardcoded API key or secret found",
          Severity::High,
        ));
      }
    }

    issues
  }
}

fn create_issue(
  analyzer_name: &str,
  context: &FileContext,
  line_num: usize,
  line: &str,
  message: &str,
  severity: Severity,
) -> Issue {
  let id =
    generate_issue_id(analyzer_name, context.file_path.to_str().unwrap_or(""), line_num, message);

  Issue {
    issue_type: analyzer_name.to_string(),
    line: line_num,
    message: message.to_string(),
    severity,
    code: Some(redact_secret(line)),
    analyzer: Some(analyzer_name.to_string()),
    id: Some(id),
  }
}

fn redact_secret(line: &str) -> String {
  let trimmed = line.trim();
  if trimmed.len() > 80 {
    format!("{}...[REDACTED]", &trimmed[..40])
  } else {
    trimmed.to_string()
  }
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

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
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

    let source = r#"const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
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

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
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

    let source = r#"const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012";"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
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

    // npm_ + 36 alphanumeric characters
    let source = r#"const token = "npm_abcdefghijklmnopqrstuvwxyz1234567890";"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
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

    let source = r#"const config = { api_key: "abc123def456ghi789jkl012mno" };"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
  }

  #[test]
  fn test_ignores_safe_code() {
    let analyzer = SecretsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const apiKey = process.env.API_KEY;
const secret = getSecretFromVault();
"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert!(issues.is_empty());
  }
}
