use aho_corasick::AhoCorasick;
use lazy_static::lazy_static;

use crate::ast::{try_parse_and_walk, ArgInfo, AstVisitor, CallInfo};
use crate::util::{generate_issue_id, is_suspicious_url};

use super::{FileAnalyzer, FileContext, Issue, Severity};

const NETWORK_FUNCTIONS: &[&str] = &["fetch", "axios", "got", "request"];

const HTTP_METHODS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

const SOCKET_FUNCTIONS: &[&str] = &["connect", "createConnection"];

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
  source: &'a str,
  allowed_hosts: Vec<String>,
}

impl<'a> NetworkVisitor<'a> {
  fn get_code_at_line(&self, line: usize) -> String {
    self.source.lines().nth(line.saturating_sub(1)).unwrap_or("").trim().to_string()
  }

  fn is_allowed_url(&self, url: &str) -> bool {
    self.allowed_hosts.iter().any(|h| url.contains(h))
  }

  fn check_url_string(&mut self, url: &str, line: usize) {
    if self.is_allowed_url(url) {
      return;
    }

    let severity = if is_suspicious_url(url) { Severity::Critical } else { Severity::Medium };

    let message = if is_suspicious_url(url) {
      format!("Suspicious URL detected: {}", url)
    } else {
      format!("Network URL found: {}", url)
    };

    let id = generate_issue_id(self.analyzer_name, self.file_path, line, &message);

    self.issues.push(Issue {
      issue_type: self.analyzer_name.to_string(),
      line,
      message,
      severity,
      code: Some(self.get_code_at_line(line)),
      analyzer: Some(self.analyzer_name.to_string()),
      id: Some(id),
    });
  }
}

impl AstVisitor for NetworkVisitor<'_> {
  fn visit_call(&mut self, call: &CallInfo) {
    let line = call.line.max(1);

    // Check for direct network function calls: fetch(), axios(), got(), request()
    if let Some(ref callee) = call.callee_name {
      if NETWORK_FUNCTIONS.contains(&callee.as_str()) {
        let message = "HTTP request function detected";
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

        // Check if first argument is a URL string
        if !call.arguments.is_empty() {
          if let ArgInfo::StringLiteral(url) = &call.arguments[0] {
            if url.starts_with("http://")
              || url.starts_with("https://")
              || url.starts_with("ws://")
              || url.starts_with("wss://")
            {
              self.check_url_string(url, line);
            }
          }
        }
      }

      // Check for new WebSocket()
      if callee == "WebSocket" {
        let message = "Socket connection detected";
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
    }

    // Check for http.get(), https.post(), axios.get(), etc.
    if let (Some(ref callee), Some(ref object)) = (&call.callee_name, &call.object_name) {
      // http/https module methods
      if (object == "http" || object == "https") && HTTP_METHODS.contains(&callee.as_str()) {
        let message = "HTTP request function detected";
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

      // net.connect(), net.createConnection(), socket.connect()
      if (object == "net" || object == "socket") && SOCKET_FUNCTIONS.contains(&callee.as_str()) {
        let message = "Socket connection detected";
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
    }
  }

  fn visit_string_literal(&mut self, value: &str, line: usize) {
    // Check for URL strings
    if value.starts_with("http://")
      || value.starts_with("https://")
      || value.starts_with("ftp://")
      || value.starts_with("ws://")
      || value.starts_with("wss://")
    {
      self.check_url_string(value, line);
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

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    // Quick check - skip AST parsing if no network-related patterns found
    if !QUICK_CHECK.is_match(context.source) {
      return vec![];
    }

    let config = context.config.get_analyzer_config(self.name());
    let allowed_hosts: Vec<String> =
      config.and_then(|c| c.allowed_hosts.clone()).unwrap_or_default();

    let mut visitor = NetworkVisitor {
      issues: vec![],
      analyzer_name: self.name(),
      file_path: context.file_path.to_str().unwrap_or(""),
      source: context.source,
      allowed_hosts,
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
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
  }

  #[test]
  fn test_detects_suspicious_url() {
    let analyzer = NetworkAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const url = "https://evil.ngrok.io/callback";"#;

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    let has_suspicious =
      issues.iter().any(|i| i.message.contains("Suspicious") || i.message.contains("ngrok"));
    assert!(has_suspicious);
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
    };
    let issues = analyzer.analyze(&context);

    let socket_issues: Vec<_> =
      issues.iter().filter(|i| i.message.contains("Socket connection")).collect();
    assert!(!socket_issues.is_empty());
  }
}
