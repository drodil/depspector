use super::{FileAnalyzer, FileContext, Issue, Severity};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::Ipv4Addr;

lazy_static! {
  static ref IPV4_REGEX: Regex = Regex::new(
    r#"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"#
  )
  .unwrap();
}

pub struct IpAnalyzer;

impl FileAnalyzer for IpAnalyzer {
  fn name(&self) -> &'static str {
    "ip"
  }

  fn uses_ast(&self) -> bool {
    true
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    let Some(ast) = context.parsed_ast else {
      return issues;
    };

    let config = context.config.get_analyzer_config(self.name());
    let allowed_ips = config.and_then(|c| c.allowed_ips.clone()).unwrap_or_default();

    // file_path not needed here; other variables use `context.file_path` directly

    for string_lit in &ast.string_literals {
      let ip_str = &string_lit.value;

      if allowed_ips.iter().any(|allowed| allowed == ip_str) {
        continue;
      }

      if IPV4_REGEX.is_match(ip_str) {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
          if is_public_ip(ip) {
            let line = string_lit.line.max(1);
            let message = format!("Hardcoded public IP address found: {}", ip_str);

            let file_path_str = context.file_path.to_str().unwrap_or("unknown");
            let mut issue =
              Issue::new(self.name(), message, Severity::Medium, file_path_str.to_string())
                .with_line(line)
                .with_code(ip_str.to_string());
            if let Some(pkg) = context.package_name {
              issue = issue.with_package_name(pkg);
            }
            issues.push(issue);
          }
        }
      }
    }

    issues
  }
}

fn is_public_ip(ip: Ipv4Addr) -> bool {
  if ip.is_loopback() {
    return false;
  }

  if ip.is_private() {
    return false;
  }

  if ip.is_link_local() {
    return false;
  }

  let octets = ip.octets();
  if octets[0] == 172 && (16..=31).contains(&octets[1]) {
    return false;
  }

  if octets[0] == 0 {
    return false;
  }

  if ip.is_multicast() {
    return false;
  }

  if ip.is_broadcast() {
    return false;
  }

  true
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_public_ip() {
    let analyzer = IpAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");
    let source = "const ip = '8.8.8.8';";

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: ast.as_ref(),
    };

    let issues = analyzer.analyze(&context);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("8.8.8.8"));
  }

  #[test]
  fn test_ignores_private_ip() {
    let analyzer = IpAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");
    let source = "const ip = '192.168.1.1';";

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: ast.as_ref(),
    };

    let issues = analyzer.analyze(&context);
    assert!(issues.is_empty());
  }

  #[test]
  fn test_ignores_localhost() {
    let analyzer = IpAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");
    let source = "const ip = '127.0.0.1';";

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: ast.as_ref(),
    };

    let issues = analyzer.analyze(&context);
    assert!(issues.is_empty());
  }

  #[test]
  fn test_allowed_ips_config() {
    let analyzer = IpAnalyzer;
    let mut config = crate::config::Config::default();

    let analyzer_config = crate::config::AnalyzerConfig { allowed_ips: Some(vec!["8.8.8.8".to_string()]), ..Default::default() };
    config.analyzers.insert("ip".to_string(), analyzer_config);

    let file_path = PathBuf::from("test.js");
    let source = "const ip = '8.8.8.8';";

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: ast.as_ref(),
    };

    let issues = analyzer.analyze(&context);
    assert!(issues.is_empty());
  }

  #[test]
  fn test_ignores_ip_in_comments() {
    let analyzer = IpAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");
    let source = r#"
      // This IP is public: 8.8.8.8
      /* Another comment with 1.2.3.4 */
      const valid = '192.168.1.1';
    "#;

    let ast = crate::ast::ParsedAst::parse(source);
    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: ast.as_ref(),
    };

    let issues = analyzer.analyze(&context);
    // Should not detect IPs in comments, only private IP in string
    assert!(issues.is_empty());
  }
}
