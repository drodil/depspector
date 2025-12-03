use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast_filtered, AstVisitor, CallInfo, NodeInterest};
use crate::util::{generate_issue_id, LineIndex};

use super::{FileAnalyzer, FileContext, Issue, Severity};

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick = AhoCorasick::new([
    "os.userInfo",
    "os.networkInterfaces",
    "os.platform",
    "os.hostname",
    "os.release",
    "os.arch",
    "os.cpus",
    "os.totalmem",
    "os.freemem",
    "os.homedir",
    "os.tmpdir",
  ])
  .unwrap();
}

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
  package_name: Option<&'a str>,
  line_index: LineIndex,
}

impl AstVisitor for MetadataVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    // Check for os.* method calls
    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      if object == "os" && SUSPICIOUS_OS_METHODS.contains(&callee.as_str()) {
        let line = call.line.max(1);
        let message = format!("Suspicious system metadata collection detected: os.{}()", callee);

        let id =
          generate_issue_id(self.analyzer_name, self.file_path, line, &message, self.package_name);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message,
          severity: Severity::Low,
          code: Some(self.line_index.get_line(line)),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
          file: None,
        });
      }
    }
  }
}

impl FileAnalyzer for MetadataAnalyzer {
  fn name(&self) -> &'static str {
    "metadata"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip if no os.* method patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let mut visitor = MetadataVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      package_name: context.package_name,
      line_index: LineIndex::new(context.source),
    };

    let interest = NodeInterest::none().with_calls();
    walk_ast_filtered(context.parsed_ast, context.source, &mut visitor, interest);

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
      parsed_ast: None,
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
      parsed_ast: None,
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
      parsed_ast: None,
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
      parsed_ast: None,
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
      parsed_ast: None,
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
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 3);
  }
}
