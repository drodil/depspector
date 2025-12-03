use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{walk_ast_filtered, AstVisitor, CallInfo, NodeInterest, VariableMap};
use crate::util::{generate_issue_id, LineIndex};

use super::{FileAnalyzer, FileContext, Issue, Severity};

const NETWORK_FUNCTIONS: &[&str] = &["fetch", "axios", "got", "request"];

const HTTP_METHODS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

const SOCKET_FUNCTIONS: &[&str] = &["connect", "createConnection"];

// Default allowed hosts - common safe domains for npm packages
const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "npm.pkg.github.com",
  "github.com",
  "raw.githubusercontent.com",
  "api.github.com",
  "gitlab.com",
  "bitbucket.org",
  "npmjs.com",
  "unpkg.com",
  "cdn.jsdelivr.net",
  "esm.sh",
  "deno.land",
];

// Quick-check patterns for early bail-out
const QUICK_CHECK_PATTERNS: &[&str] = &[
  "fetch",
  "axios",
  "got",
  "request",
  "http://",
  "https://",
  "ftp://",
  "ws://",
  "wss://",
  "WebSocket",
  "http.",
  "https.",
  "net.",
  "socket.",
];

lazy_static! {
  static ref QUICK_CHECK: AhoCorasick = AhoCorasick::new(QUICK_CHECK_PATTERNS).unwrap();
}

pub struct NetworkAnalyzer;

struct NetworkVisitor<'a> {
  issues: Vec<Issue>,
  analyzer_name: &'static str,
  file_path: &'a str,
  package_name: Option<&'a str>,
  line_index: LineIndex,
  allowed_hosts: Vec<String>,
  variable_map: VariableMap,
}

impl NetworkVisitor<'_> {
  fn is_allowed_url(&self, url: &str) -> bool {
    self.allowed_hosts.iter().any(|h| url.contains(h))
  }

  fn check_url_string(&mut self, url: &str, line: usize) {
    if self.is_allowed_url(url) {
      return;
    }

    let message = "HTTP request detected".to_string();
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
}

impl AstVisitor for NetworkVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    if let Some(ref callee) = call.callee_name {
      if NETWORK_FUNCTIONS.contains(&callee.as_str()) && !call.arguments.is_empty() {
        // Resolve the URL argument (handles string literals, template literals, and variables)
        if let Some(url) = self.variable_map.resolve_arg(&call.arguments[0]) {
          if url.starts_with("http://")
            || url.starts_with("https://")
            || url.starts_with("ws://")
            || url.starts_with("wss://")
          {
            self.check_url_string(&url, line);
          }
        }
      }

      if callee == "WebSocket" {
        let message = "Socket connection detected";
        let id =
          generate_issue_id(self.analyzer_name, self.file_path, line, message, self.package_name);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message: message.to_string(),
          severity: Severity::High,
          code: Some(self.line_index.get_line(line)),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
          file: None,
        });
      }
    }

    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      // http/https module methods
      if (object == "http" || object == "https") && HTTP_METHODS.contains(&callee.as_str()) {
        let message = "HTTP request function detected";
        let id =
          generate_issue_id(self.analyzer_name, self.file_path, line, message, self.package_name);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message: message.to_string(),
          severity: Severity::Medium,
          code: Some(self.line_index.get_line(line)),
          analyzer: Some(self.analyzer_name.to_string()),
          id: Some(id),
          file: None,
        });
      }

      if (object == "net" || object == "socket") && SOCKET_FUNCTIONS.contains(&callee.as_str()) {
        let message = "Socket connection detected";
        let id =
          generate_issue_id(self.analyzer_name, self.file_path, line, message, self.package_name);

        self.issues.push(Issue {
          issue_type: self.analyzer_name.to_string(),
          line,
          message: message.to_string(),
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

impl FileAnalyzer for NetworkAnalyzer {
  fn name(&self) -> &'static str {
    "network"
  }

  fn requires_network(&self) -> bool {
    false
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no network-related patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let config = context.config.get_analyzer_config(self.name());
    let allowed_hosts: Vec<String> = config
      .and_then(|c| c.allowed_hosts.clone())
      .unwrap_or_else(|| DEFAULT_ALLOWED_HOSTS.iter().map(|s| s.to_string()).collect());

    // Use pre-built variable map from ParsedAst for resolving identifier arguments
    let variable_map = context.parsed_ast.map(|ast| ast.variable_map.clone()).unwrap_or_default();

    let mut visitor = NetworkVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      package_name: context.package_name,
      line_index: LineIndex::new(context.source),
      allowed_hosts,
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
  fn test_detects_url() {
    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"fetch("https://api.example.com/data");"#;

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
  fn test_ignores_url_constants() {
    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // URL constants/templates should not be flagged - only actual network calls
    let source = r#"const url = "https://example.com/callback";"#;

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
  fn test_allowed_hosts() {
    let analyzer = NetworkAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.allowed_hosts = Some(vec!["example.com".to_string()]);
    config.analyzers.insert("network".to_string(), analyzer_config);

    let source = r#"fetch("https://api.example.com/data");"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    let url_issues: Vec<_> = issues.iter().filter(|i| i.message.contains("example.com")).collect();
    assert!(url_issues.is_empty());
  }

  #[test]
  fn test_detects_http_get() {
    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"http.get("https://api.example.com/data");"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    let http_issues: Vec<_> =
      issues.iter().filter(|i| i.message.contains("HTTP request")).collect();
    assert!(!http_issues.is_empty());
  }

  #[test]
  fn test_detects_websocket() {
    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const ws = new WebSocket("wss://stream.example.com");"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    let socket_issues: Vec<_> =
      issues.iter().filter(|i| i.message.contains("Socket connection")).collect();
    assert!(!socket_issues.is_empty());
  }

  #[test]
  fn test_detects_net_connect() {
    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"net.connect({ port: 8080 });"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    let socket_issues: Vec<_> =
      issues.iter().filter(|i| i.message.contains("Socket connection")).collect();
    assert!(!socket_issues.is_empty());
  }

  #[test]
  fn test_detects_url_via_variable() {
    use crate::ast::ParsedAst;

    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
      const endpoint = 'https://malicious.example.com/data';
      fetch(endpoint);
    "#;

    let parsed = ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: parsed.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty(), "Should detect HTTP request via variable");
  }

  #[test]
  fn test_detects_url_via_template_interpolation() {
    use crate::ast::ParsedAst;

    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
      const host = 'evil.example.com';
      const url = `https://${host}/api`;
      fetch(url);
    "#;

    let parsed = ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: parsed.as_ref(),
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty(), "Should detect HTTP request via template interpolation");
  }
}
