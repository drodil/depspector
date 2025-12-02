use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast, ArgInfo, AstVisitor, CallInfo};
use crate::util::generate_issue_id;

use super::{FileAnalyzer, FileContext, Issue, Severity};

const DANGEROUS_FUNCTIONS: &[&str] = &["eval", "Function", "setTimeout", "setInterval"];

lazy_static! {
  // Note: 'require' is intentionally excluded - it's in nearly every file.
  // Dynamic require detection is triggered by the other patterns or specific contexts.
  static ref QUICK_CHECK: AhoCorasick =
    AhoCorasick::new(["eval", "new Function", "Function(",]).unwrap();
}

pub struct EvalAnalyzer;

struct EvalVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  source: &'a str,
}

impl<'a> EvalVisitor<'a> {
  fn get_line_for_call(&self, call: &CallInfo) -> usize {
    // Use the line from CallInfo, or estimate from source
    call.line.max(1)
  }

  fn get_code_at_line(&self, line: usize) -> String {
    self.source.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string()
  }
}

impl AstVisitor for EvalVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    if let Some(ref callee) = call.callee_name {
      if DANGEROUS_FUNCTIONS.contains(&callee.as_str()) {
        if (callee == "setTimeout" || callee == "setInterval")
          && !call.arguments.is_empty()
          && !matches!(&call.arguments[0], ArgInfo::StringLiteral(_))
        {
          return;
        }

        let line = self.get_line_for_call(call);
        let message = format!("Use of {}() detected. This can execute arbitrary code.", callee);

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
        match &call.arguments[0] {
          ArgInfo::StringLiteral(_) => {
            // Static require - safe
          }
          ArgInfo::Identifier(_) | ArgInfo::BinaryExpr | ArgInfo::TemplateLiteral(_) => {
            let line = self.get_line_for_call(call);
            let message = "Dynamic require() detected. Module path determined at runtime.";

            let id = generate_issue_id(self.analyzer_name, self.file_path, line, message);

            self.issues.push(Issue {
              issue_type: self.analyzer_name.to_string(),
              line,
              message: message.to_string(),
              severity: Severity::High,
              code: Some(self.get_code_at_line(line)),
              analyzer: Some(self.analyzer_name.to_string()),
              id: Some(id),
            });
          }
          _ => {}
        }
      }
    }
  }
}

impl FileAnalyzer for EvalAnalyzer {
  fn name(&self) -> &'static str {
    "eval"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip if no dangerous patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let mut visitor = EvalVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      source: context.source,
    };

    walk_ast(context.parsed_ast, context.source, &mut visitor);

    visitor.issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_eval() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"eval("console.log('hello')");"#;

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
  }

  #[test]
  fn test_detects_function_constructor() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"new Function("return this")();"#;

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
  fn test_ignores_safe_require() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const fs = require('fs');"#;

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
