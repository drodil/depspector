use crate::ast::{try_parse_and_walk, AstVisitor, CallInfo};
use crate::util::generate_issue_id;

use super::{FileAnalyzer, FileContext, Issue, Severity};

const SUSPICIOUS_OS_METHODS: &[&str] = &[
  "userInfo",
  "networkInterfaces",
  "platform",
  "hostname",
  "release",
  "arch",
  "cpus",
  "totalmem",
  "freemem",
  "homedir",
  "tmpdir",
];

pub struct MetadataAnalyzer;

struct MetadataVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  source: &'a str,
}

impl<'a> MetadataVisitor<'a> {
  fn get_code_at_line(&self, line: usize) -> String {
    self.source.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string()
  }
}

impl AstVisitor for MetadataVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    // Check for os.* method calls
    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      if object == "os" && SUSPICIOUS_OS_METHODS.contains(&callee.as_str()) {
        let line = call.line.max(1);
        let message = format!("Suspicious system metadata collection detected: os.{}()", callee);

        let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message,
          severity: Severity::Low,
          code: Some(self.get_code_at_line(line)),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
        });
      }
    }
  }
}

impl FileAnalyzer for MetadataAnalyzer {
  fn name(&self) -> &'static str {
    "metadata"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut visitor = MetadataVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      source: context.source,
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
  fn test_detects_user_info() {
    let analyzer = MetadataAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const info = os.userInfo();"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("userInfo"));
  }

  #[test]
  fn test_detects_network_interfaces() {
    let analyzer = MetadataAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const nets = os.networkInterfaces();"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("networkInterfaces"));
  }

  #[test]
  fn test_detects_hostname() {
    let analyzer = MetadataAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const host = os.hostname();"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
  }

  #[test]
  fn test_detects_platform() {
    let analyzer = MetadataAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"if (os.platform() === 'win32') {}"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
  }

  #[test]
  fn test_ignores_non_suspicious_methods() {
    let analyzer = MetadataAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"os.EOL;"#;

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
  fn test_detects_multiple_calls() {
    let analyzer = MetadataAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const info = os.userInfo();
const host = os.hostname();
const platform = os.platform();
"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 3);
  }
}
