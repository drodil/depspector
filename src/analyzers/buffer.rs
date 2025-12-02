use lazy_static::lazy_static;
use regex::Regex;

use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;

pub struct BufferAnalyzer;

lazy_static! {
  static ref BUFFER_PATTERN: Regex =
    Regex::new(r#"Buffer\.(from|alloc)\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap();
}

impl FileAnalyzer for BufferAnalyzer {
  fn name(&self) -> &'static str {
    "buffer"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    if !context.source.contains("Buffer.") {
      return vec![];
    }

    let mut issues = vec![];

    let config = context.config.get_analyzer_config(self.name());
    let min_length = config.and_then(|c| c.min_buffer_length).unwrap_or(100);

    for (line_num, line) in context.source.lines().enumerate() {
      if !line.contains("Buffer.") {
        continue;
      }
      for cap in BUFFER_PATTERN.captures_iter(line) {
        if let Some(data) = cap.get(2) {
          let data_str = data.as_str();
          if data_str.len() >= min_length {
            let message = format!(
              "Large encoded buffer detected ({} chars). May contain hidden payload.",
              data_str.len()
            );

            let id = generate_issue_id(
              self.name(),
              context.file_path.to_str().unwrap_or(""),
              line_num + 1,
              &message,
            );

            issues.push(Issue {
              issue_type: self.name().to_string(),
              line: line_num + 1,
              message,
              severity: Severity::High,
              code: Some(line.trim().to_string()),
              analyzer: Some(self.name().to_string()),
              id: Some(id),
              file: None,
            });
          }
        }
      }
    }

    issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_large_buffer() {
    let analyzer = BufferAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let large_data = "a".repeat(150);
    let source = format!(r#"const buf = Buffer.from("{}");"#, large_data);

    let context = FileContext {
      source: &source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::High);
  }

  #[test]
  fn test_ignores_small_buffer() {
    let analyzer = BufferAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const buf = Buffer.from("hello");"#;

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
  fn test_respects_config_threshold() {
    let analyzer = BufferAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.min_buffer_length = Some(10);
    config.analyzers.insert("buffer".to_string(), analyzer_config);

    let source = r#"const buf = Buffer.from("hello world!");"#;

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
  }
}
