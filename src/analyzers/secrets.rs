use lazy_static::lazy_static;
use regex::Regex;

use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;

use regex::RegexSet;

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

    static ref SECRETS_SET: RegexSet = RegexSet::new(&[
        r#"AKIA[0-9A-Z]{16}"#, // 0: AWS
        r#"-----BEGIN RSA PRIVATE KEY-----"#, // 1: RSA
        r#"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----"#, // 2: Private Key
        r#"sk_live_[0-9a-zA-Z]{24,}"#, // 3: Stripe
        r#"gh[pousr]_[A-Za-z0-9_]{36,}"#, // 4: GitHub
        r#"npm_[A-Za-z0-9]{36,}"#, // 5: NPM
        r#"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}"#, // 6: Slack
        r#"AIza[0-9A-Za-z\-_]{35}"#, // 7: Google
        r#"SK[0-9a-fA-F]{32}"#, // 8: Twilio
        r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#, // 9: Generic
    ]).unwrap();
}

pub struct SecretsAnalyzer;

impl FileAnalyzer for SecretsAnalyzer {
  fn name(&self) -> &'static str {
    "secrets"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    for (line_num, line) in context.source.lines().enumerate() {
      // Use RegexSet to check if any pattern matches before running individual regexes
      let matches = SECRETS_SET.matches(line);
      if !matches.matched_any() {
        continue;
      }

      if matches.matched(0) && AWS_ACCESS_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential AWS Access Key ID found",
          Severity::Critical,
        ));
      }

      if (matches.matched(1) || matches.matched(2)) && (RSA_PRIVATE_KEY.is_match(line) || PRIVATE_KEY.is_match(line)) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Private Key found",
          Severity::Critical,
        ));
      }

      if matches.matched(3) && STRIPE_SECRET.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Stripe Secret Key found",
          Severity::Critical,
        ));
      }

      if matches.matched(4) && GITHUB_TOKEN.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential GitHub Token found",
          Severity::Critical,
        ));
      }

      if matches.matched(5) && NPM_TOKEN.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential npm Token found",
          Severity::Critical,
        ));
      }

      if matches.matched(6) && SLACK_TOKEN.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Slack Token found",
          Severity::Critical,
        ));
      }

      if matches.matched(7) && GOOGLE_API_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Google API Key found",
          Severity::High,
        ));
      }

      if matches.matched(8) && TWILIO_KEY.is_match(line) {
        issues.push(create_issue(
          self.name(),
          context,
          line_num + 1,
          line,
          "Potential Twilio API Key found",
          Severity::Critical,
        ));
      }

      if matches.matched(9)
        && GENERIC_API_KEY.is_match(line)
        && !matches.matched(0) // Not AWS
        && !matches.matched(3) // Not Stripe
        && !matches.matched(4) // Not GitHub
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
