use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast_filtered, AstVisitor, DestructureInfo, MemberAccessInfo, NodeInterest};
use crate::util::LineIndex;

use super::{FileAnalyzer, FileContext, Issue, Severity};

// Common Node.js environment variables that are typically safe
const DEFAULT_ALLOWED_ENV_VARS: &[&str] = &[
  "NODE_ENV",
  "DEBUG",
  "PORT",
  "HOST",
  "HOSTNAME",
  "PATH",
  "HOME",
  "USER",
  "SHELL",
  "LANG",
  "LC_ALL",
  "TZ",
  "CI",
  "npm_package_name",
  "npm_package_version",
  "npm_lifecycle_event",
  "NODE_DEBUG",
  "NODE_OPTIONS",
  "NODE_PATH",
  "UV_THREADPOOL_SIZE",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NO_COLOR",
  "FORCE_COLOR",
  "TERM",
  "COLORTERM",
  "PWD",
  "OLDPWD",
  "TMPDIR",
  "TEMP",
  "TMP",
];

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick = AhoCorasick::new(["process.env", "process["]).unwrap();
}

pub struct EnvAnalyzer;

struct EnvVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  package_name: Option<&'a str>,
  line_index: LineIndex,
  allowed_vars: Vec<String>,
}

impl EnvVisitor<'_> {
  fn add_env_issue(&mut self, var_name: &str, line: usize) {
    if self.allowed_vars.contains(&var_name.to_string()) {
      return;
    }

    let message = format!("Access to process.env.{} detected", var_name);

    let severity = if is_sensitive_env_var(var_name) { Severity::Medium } else { Severity::Low };

    self.issues.push(
      Issue::new(self.analyzer_name, message, severity, self.file_path.to_string())
        .with_package_name(self.package_name.unwrap_or("unknown"))
        .with_line(line)
        .with_code(self.line_index.get_line(line)),
    );
  }
}

fn is_sensitive_env_var(var_name: &str) -> bool {
  let upper = var_name.to_uppercase();

  upper.contains("KEY")
    || upper.contains("TOKEN")
    || upper.contains("SECRET")
    || upper.contains("PASSWORD")
    || upper.contains("PASSWD")
    || upper.contains("CREDENTIALS")
    || upper.contains("AUTH")
    || upper.contains("API")
    || upper.contains("PRIVATE")
    || upper.contains("CERT")
    || upper.contains("SIGNATURE")
}

impl AstVisitor for EnvVisitor<'_> {
  fn visit_member_access(&mut self, access: &MemberAccessInfo) {
    if access.object == "process"
      && !access.properties.is_empty()
      && access.properties[0] == "env"
      && access.properties.len() > 1
    {
      let var_name = &access.properties[1];
      let line = access.line.max(1);
      self.add_env_issue(var_name, line);
    }
  }

  fn visit_destructure(&mut self, destructure: &DestructureInfo) {
    if destructure.source_object == "process"
      && destructure.source_property.as_deref() == Some("env")
    {
      let line = destructure.line.max(1);
      for name in &destructure.names {
        self.add_env_issue(name, line);
      }
    }
  }
}

impl FileAnalyzer for EnvAnalyzer {
  fn name(&self) -> &'static str {
    "env"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no process.env pattern found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let config = context.config.get_analyzer_config(self.name());
    let allowed_vars: Vec<String> = config
      .and_then(|c| c.allowed_env_vars.clone())
      .unwrap_or_else(|| DEFAULT_ALLOWED_ENV_VARS.iter().map(|s| s.to_string()).collect());

    let mut visitor = EnvVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      package_name: context.package_name,
      line_index: LineIndex::new(context.source),
      allowed_vars,
    };

    let interest = NodeInterest::none().with_member_accesses().with_destructures();
    walk_ast_filtered(context.parsed_ast, context.source, &mut visitor, interest);

    visitor.issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_env_access() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const apiKey = process.env.API_KEY;"#;

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
    assert!(issues[0].message.contains("API_KEY"));
    assert_eq!(issues[0].severity, Severity::Medium); // API_KEY should be medium
  }

  #[test]
  fn test_detects_bracket_access() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const secret = process.env['SECRET_TOKEN'];"#;

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
    assert!(issues[0].message.contains("SECRET_TOKEN"));
    assert_eq!(issues[0].severity, Severity::Medium); // SECRET and TOKEN should be medium
  }

  #[test]
  fn test_detects_destructuring() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Use non-default env vars to test detection
    let source = r#"const { SECRET_KEY, API_TOKEN } = process.env;"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 2);
    // Both should be medium severity due to SECRET/KEY and API/TOKEN patterns
    assert!(issues.iter().all(|i| i.severity == Severity::Medium));
  }

  #[test]
  fn test_low_severity_for_non_sensitive_vars() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const env = process.env.MY_CUSTOM_VAR;"#;

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
    assert_eq!(issues[0].severity, Severity::Low); // Non-sensitive var should be low
  }

  #[test]
  fn test_allowed_variables() {
    let analyzer = EnvAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Override defaults with custom allowed list including CUSTOM_VAR
    let analyzer_config = crate::config::AnalyzerConfig {
      allowed_env_vars: Some(vec!["CUSTOM_VAR".to_string()]),
      ..Default::default()
    };
    config.analyzers.insert("env".to_string(), analyzer_config);

    let source = r#"const env = process.env.CUSTOM_VAR;"#;

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

  #[test]
  fn test_default_allowed_variables() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // NODE_ENV should be allowed by default
    let source = r#"const env = process.env.NODE_ENV;"#;

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

  #[test]
  fn test_ignores_non_env_access() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const value = config.env.setting;"#;

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
