use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;
use lazy_static::lazy_static;
use regex::Regex;
use std::net::Ipv4Addr;

lazy_static! {
    static ref IPV4_REGEX: Regex = Regex::new(
        r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#
    ).unwrap();
}

pub struct IpAnalyzer;

impl FileAnalyzer for IpAnalyzer {
  fn name(&self) -> &'static str {
    "ip"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    let config = context.config.get_analyzer_config(self.name());
    let allowed_ips = config.and_then(|c| c.allowed_ips.clone()).unwrap_or_default();

    for mat in IPV4_REGEX.find_iter(context.source) {
      let ip_str = mat.as_str();

      if allowed_ips.iter().any(|allowed| allowed == ip_str) {
        continue;
      }

      if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        if is_public_ip(ip) {
          let start = mat.start();
          let source_bytes = context.source.as_bytes();

          if start > 0 {
            let prev_char = source_bytes[start - 1] as char;
            if prev_char == 'v' || prev_char == 'V' {
              continue;
            }
          }

          let line_num = context.source[..start].lines().count();
          let message = format!("Hardcoded public IP address found: {}", ip_str);

          let id = generate_issue_id(
            self.name(),
            context.file_path.to_str().unwrap_or(""),
            line_num,
            &message,
            context.package_name,
          );

          issues.push(Issue {
            issue_type: self.name().to_string(),
            line: line_num,
            message,
            severity: Severity::Medium,
            code: Some(ip_str.to_string()),
            analyzer: Some(self.name().to_string()),
            id: Some(id),
            file: None,
          });
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

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: None,
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

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: None,
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

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: None,
    };

    let issues = analyzer.analyze(&context);
    assert!(issues.is_empty());
  }

  #[test]
  fn test_allowed_ips_config() {
    let analyzer = IpAnalyzer;
    let mut config = crate::config::Config::default();

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.allowed_ips = Some(vec!["8.8.8.8".to_string()]);
    config.analyzers.insert("ip".to_string(), analyzer_config);

    let file_path = PathBuf::from("test.js");
    let source = "const ip = '8.8.8.8';";

    let context = FileContext {
      source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: None,
    };

    let issues = analyzer.analyze(&context);
    assert!(issues.is_empty());
  }
}
