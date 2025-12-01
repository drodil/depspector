use crate::ast::{try_parse_and_walk, AstVisitor, DestructureInfo, MemberAccessInfo};
use crate::util::generate_issue_id;

use super::{FileAnalyzer, FileContext, Issue, Severity};

pub struct EnvAnalyzer;

struct EnvVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  source: &'a str,
  allowed_vars: Vec<String>,
}

impl<'a> EnvVisitor<'a> {
  fn get_code_at_line(&self, line: usize) -> String {
    self.source.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string()
  }

  fn add_env_issue(&mut self, var_name: &str, line: usize) {
    if self.allowed_vars.contains(&var_name.to_string()) {
      return;
    }

    let message = format!("Access to process.env.{} detected", var_name);
    let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

    self.issues.push(Issue {
      issue_type: self.analyzer_name.to_string(),
      line,
      message,
      severity: Severity::Medium,
      code: Some(self.get_code_at_line(line)),
      analyzer: Some(self.analyzer_name.to_string()),
      id: Some(id),
    });
  }
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
    // Check for `const { VAR1, VAR2 } = process.env`
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

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no process.env pattern found
    if !context.source.contains("process.env") && !context.source.contains("process[") {
      return vec![];
    }

    let config = context.config.get_analyzer_config(self.name());
    let allowed_vars: Vec<String> =
      config.and_then(|c| c.allowed_env_vars.clone()).unwrap_or_default();

    let mut visitor = EnvVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      source: context.source,
      allowed_vars,
    };

    try_parse_and_walk(context.source, &mut visitor);
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
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("API_KEY"));
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
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("SECRET_TOKEN"));
  }

  #[test]
  fn test_detects_destructuring() {
    let analyzer = EnvAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const { NODE_ENV, API_KEY } = process.env;"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 2);
  }

  #[test]
  fn test_allowed_variables() {
    let analyzer = EnvAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.allowed_env_vars = Some(vec!["NODE_ENV".to_string()]);
    config.analyzers.insert("env".to_string(), analyzer_config);

    let source = r#"const env = process.env.NODE_ENV;"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
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
    };
    let issues = analyzer.analyze(&context);

    assert!(issues.is_empty());
  }
}
