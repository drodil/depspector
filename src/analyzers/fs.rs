use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast_filtered, ArgInfo, AstVisitor, CallInfo, NodeInterest};
use crate::util::{generate_issue_id, LineIndex};

use super::{FileAnalyzer, FileContext, Issue, Severity};

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick = AhoCorasick::new(["fs.", "promises."]).unwrap();
}

const DEFAULT_DANGEROUS_PATHS: &[&str] = &[
  "/etc/passwd",
  "/etc/shadow",
  "/etc/hosts",
  "/etc/group",
  "/proc/self/environ",
  "/proc/self/cmdline",
  "/proc/self/cwd",
  ".ssh",
  "id_rsa",
  "id_ed25519",
  "authorized_keys",
  "known_hosts",
  ".npmrc",
  ".yarnrc",
  ".npmrc.yaml",
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".aws/credentials",
  ".aws/config",
  ".git/config",
  ".git/credentials",
  ".gitconfig",
  ".git-credentials",
  ".docker/config.json",
  ".kube/config",
  "kubeconfig",
  ".azure/credentials",
  ".config/gcloud",
  ".pgpass",
  ".my.cnf",
  ".redis/redis.conf",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".crt",
  ".csr",
  "private_key",
  "privatekey",
  ".bash_history",
  ".zsh_history",
  ".sh_history",
  "C:\\Windows\\System32\\config\\SAM",
  "C:\\Windows\\System32\\config\\SYSTEM",
  "NTUSER.DAT",
];

const WRITE_METHODS: &[&str] = &["writeFile", "writeFileSync", "appendFile", "appendFileSync"];

pub struct FsAnalyzer;

struct FsVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  line_index: LineIndex,
  dangerous_paths: Vec<&'a str>,
}

impl FsVisitor<'_> {
  fn check_dangerous_path(&self, path: &str) -> bool {
    self.dangerous_paths.iter().any(|dangerous| path.contains(dangerous))
  }
}

impl AstVisitor for FsVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      if object == "fs" || object == "promises" {
        if !call.arguments.is_empty() {
          if let ArgInfo::StringLiteral(path) = &call.arguments[0] {
            if self.check_dangerous_path(path) {
              let message = format!("Suspicious file access detected: {}", path);

              let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

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

        // Check for write operations
        if WRITE_METHODS.contains(&callee.as_str()) {
          let message = format!("File write operation detected ({})", callee);

          let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

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

        // Check for watch operations
        if callee == "watch" {
          let message = "File watch operation detected (fs.watch)".to_string();

          let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

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
    }
  }
}

impl FileAnalyzer for FsAnalyzer {
  fn name(&self) -> &'static str {
    "fs"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no fs-related patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let config = context.config.get_analyzer_config(self.name());
    let additional_paths: Vec<String> =
      config.and_then(|c| c.additional_dangerous_paths.clone()).unwrap_or_default();

    let mut dangerous_paths: Vec<&str> = DEFAULT_DANGEROUS_PATHS.to_vec();
    for path in &additional_paths {
      dangerous_paths.push(path.as_str());
    }

    let mut visitor = FsVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      line_index: LineIndex::new(context.source),
      dangerous_paths,
    };

    let interest = NodeInterest::none().with_calls().with_string_literals();
    walk_ast_filtered(context.parsed_ast, context.source, &mut visitor, interest);

    visitor.issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_dangerous_path_access() {
    let analyzer = FsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"fs.readFileSync('/etc/passwd');"#;

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
    assert!(issues[0].message.contains("/etc/passwd"));
  }

  #[test]
  fn test_detects_ssh_key_access() {
    let analyzer = FsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"fs.readFile('.ssh/id_rsa', callback);"#;

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
  fn test_detects_write_operations() {
    let analyzer = FsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"fs.writeFileSync('output.txt', data);"#;

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
    assert!(issues[0].message.contains("write"));
  }

  #[test]
  fn test_detects_watch() {
    let analyzer = FsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"fs.watch('/path/to/file', callback);"#;

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
    assert!(issues[0].message.contains("watch"));
  }

  #[test]
  fn test_additional_dangerous_paths() {
    let analyzer = FsAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.additional_dangerous_paths = Some(vec!["/custom/secret/path".to_string()]);
    config.analyzers.insert("fs".to_string(), analyzer_config);

    let source = r#"fs.readFile('/custom/secret/path/data.json');"#;

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
  fn test_ignores_safe_paths() {
    let analyzer = FsAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"fs.readFile('./package.json', callback);"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    // No dangerous path detected
    let dangerous_issues: Vec<_> =
      issues.iter().filter(|i| i.message.contains("Suspicious")).collect();
    assert!(dangerous_issues.is_empty());
  }
}
