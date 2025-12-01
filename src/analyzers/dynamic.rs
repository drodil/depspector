use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{try_parse_and_walk, ArgInfo, AstVisitor, CallInfo};
use crate::util::generate_issue_id;

use super::{FileAnalyzer, FileContext, Issue, Severity};

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick =
    AhoCorasick::new(["vm.", "require(", "require (",]).unwrap();
}

pub struct DynamicAnalyzer;

struct DynamicVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  source: &'a str,
}

impl<'a> DynamicVisitor<'a> {
  fn get_code_at_line(&self, line: usize) -> String {
    self.source.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string()
  }
}

impl AstVisitor for DynamicVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      if object == "vm"
        && (callee == "runInContext" || callee == "runInNewContext" || callee == "runInThisContext")
      {
        let message = format!("Dynamic code execution detected (vm.{})", callee);

        let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message,
          severity: Severity::Critical,
          code: Some(self.get_code_at_line(line)),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
        });
      }
    }

    if let Some(ref callee) = call.callee_name {
      if callee == "require" && !call.arguments.is_empty() {
        let is_dynamic = match &call.arguments[0] {
          ArgInfo::StringLiteral(_) => false,  // Static require - safe
          ArgInfo::Identifier(_) => true,      // Variable - dynamic
          ArgInfo::BinaryExpr => true,         // Concatenation - dynamic
          ArgInfo::TemplateLiteral(_) => true, // Template literal - dynamic
          ArgInfo::MemberExpr { .. } => true,  // Member expression - dynamic
          _ => false,
        };

        if is_dynamic {
          let message = "Dynamic require detected (argument is not a string literal)";

          let id = generate_issue_id(self.analyzer_name, self.file_path, line, message);

          self.issues.push(Issue {
            issue_type: self.analyzer_name.to_string(),
            line,
            message: message.to_string(),
            severity: Severity::Medium,
            code: Some(self.get_code_at_line(line)),
            analyzer: Some(self.analyzer_name.to_string()),
            id: Some(id),
          });
        }
      }
    }
  }
}

impl FileAnalyzer for DynamicAnalyzer {
  fn name(&self) -> &'static str {
    "dynamic"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no dynamic patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let mut visitor = DynamicVisitor {
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
  fn test_detects_vm_run_in_context() {
    let analyzer = DynamicAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"vm.runInContext(code, sandbox);"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::Critical);
    assert!(issues[0].message.contains("vm.runInContext"));
  }

  #[test]
  fn test_detects_vm_run_in_new_context() {
    let analyzer = DynamicAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"vm.runInNewContext(code);"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("vm.runInNewContext"));
  }

  #[test]
  fn test_detects_dynamic_require() {
    let analyzer = DynamicAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const mod = require(moduleName);"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::Medium);
  }

  #[test]
  fn test_ignores_static_require() {
    let analyzer = DynamicAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const fs = require('fs');"#;

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
  fn test_detects_concatenated_require() {
    let analyzer = DynamicAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const mod = require(basePath + '/module');"#;

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
}
