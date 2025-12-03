use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{
  walk_ast_filtered, ArgInfo, AssignInfo, AssignTarget, AstVisitor, CallInfo, NodeInterest,
};
use crate::util::{generate_issue_id, LineIndex};

use super::{FileAnalyzer, FileContext, Issue, Severity};

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick =
    AhoCorasick::new(
      ["__proto__", "prototype", "constructor", "setPrototypeOf", "defineProperty",]
    )
    .unwrap();
}

pub struct PollutionAnalyzer;

struct PollutionVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  package_name: Option<&'a str>,
  line_index: LineIndex,
}

impl AstVisitor for PollutionVisitor<'_> {
  fn visit_assign(&mut self, assign: &AssignInfo) {
    let line = assign.line.max(1);

    match &assign.target {
      AssignTarget::Property { object, property }
      | AssignTarget::ComputedProperty { object, property } => {
        // Check for __proto__ assignment
        if property == "__proto__" {
          let message = "Potential prototype pollution: Assignment to __proto__".to_string();

          let id = generate_issue_id(
            self.analyzer_name,
            self.file_path,
            line,
            &message,
            self.package_name,
          );

          self.issues.push(Issue {
            issue_type: self.analyzer_name.to_string(),
            line,
            message,
            severity: Severity::High,
            code: Some(self.line_index.get_line(line)),
            analyzer: Some(self.analyzer_name.to_string()),
            id: Some(id),
            file: None,
          });
        }

        // Check for constructor.prototype assignment (e.g., obj.constructor.prototype = evil)
        if property == "prototype" && object.ends_with(".constructor") {
          let message =
            "Potential prototype pollution: Assignment to constructor.prototype".to_string();

          let id = generate_issue_id(
            self.analyzer_name,
            self.file_path,
            line,
            &message,
            self.package_name,
          );

          self.issues.push(Issue {
            issue_type: self.analyzer_name.to_string(),
            line,
            message,
            severity: Severity::Medium,
            code: Some(self.line_index.get_line(line)),
            analyzer: Some(self.analyzer_name.to_string()),
            id: Some(id),
            file: None,
          });
        }

        // Check for direct constructor assignment
        if property == "constructor" {
          let message = "Potential prototype pollution: Assignment to constructor".to_string();

          let id = generate_issue_id(
            self.analyzer_name,
            self.file_path,
            line,
            &message,
            self.package_name,
          );

          self.issues.push(Issue {
            issue_type: self.analyzer_name.to_string(),
            line,
            message,
            severity: Severity::Medium,
            code: Some(self.line_index.get_line(line)),
            analyzer: Some(self.analyzer_name.to_string()),
            id: Some(id),
            file: None,
          });
        }
      }
      _ => {}
    }
  }

  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    // Check for Object.setPrototypeOf
    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      if object == "Object" && callee == "setPrototypeOf" {
        let message =
          "Object.setPrototypeOf usage detected (potential prototype pollution)".to_string();

        let id =
          generate_issue_id(self.analyzer_name, self.file_path, line, &message, self.package_name);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message,
          severity: Severity::Medium,
          code: Some(self.line_index.get_line(line)),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
          file: None,
        });
      }

      // Check for Object.defineProperty on __proto__
      if object == "Object" && callee == "defineProperty" && call.arguments.len() >= 2 {
        if let ArgInfo::StringLiteral(prop) = &call.arguments[1] {
          if prop == "__proto__" {
            let message =
              "Object.defineProperty on __proto__ detected (potential prototype pollution)"
                .to_string();

            let id = generate_issue_id(
              self.analyzer_name,
              self.file_path,
              line,
              &message,
              self.package_name,
            );

            self.issues.push(Issue {
              issue_type: self.analyzer_name.to_string(),
              line,
              message,
              severity: Severity::High,
              code: Some(self.line_index.get_line(line)),
              analyzer: Some(self.analyzer_name.to_string()),
              id: Some(id),
              file: None,
            });
          }
        }
      }
    }
  }
}

impl FileAnalyzer for PollutionAnalyzer {
  fn name(&self) -> &'static str {
    "pollution"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no pollution-related patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let mut visitor = PollutionVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      package_name: context.package_name,
      line_index: LineIndex::new(context.source),
    };

    let interest = NodeInterest::none().with_calls().with_assignments();
    walk_ast_filtered(context.parsed_ast, context.source, &mut visitor, interest);

    visitor.issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_proto_assignment() {
    let analyzer = PollutionAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"obj.__proto__ = malicious;"#;

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
    assert_eq!(issues[0].severity, Severity::High);
    assert!(issues[0].message.contains("__proto__"));
  }

  #[test]
  fn test_detects_constructor_prototype() {
    let analyzer = PollutionAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"obj.constructor.prototype = evil;"#;

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
    assert!(issues[0].message.contains("constructor.prototype"));
  }

  #[test]
  fn test_detects_set_prototype_of() {
    let analyzer = PollutionAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"Object.setPrototypeOf(target, proto);"#;

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
    assert!(issues[0].message.contains("setPrototypeOf"));
  }

  #[test]
  fn test_detects_define_property_proto() {
    let analyzer = PollutionAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"Object.defineProperty(obj, '__proto__', { value: evil });"#;

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
    assert!(issues[0].message.contains("defineProperty"));
  }

  #[test]
  fn test_detects_bracket_proto() {
    let analyzer = PollutionAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"obj['__proto__'] = evil;"#;

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
    let analyzer = PollutionAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const proto = 'hello';"#;

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
