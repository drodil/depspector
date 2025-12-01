use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;

pub struct MinifiedAnalyzer;

const MIN_LONG_LINE_LENGTH: usize = 1000;
const MIN_CODE_LENGTH: usize = 500;
const MAX_WHITESPACE_RATIO: f64 = 0.05;

impl FileAnalyzer for MinifiedAnalyzer {
  fn name(&self) -> &'static str {
    "minified"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    let lines: Vec<&str> = context.source.lines().collect();

    let long_lines: Vec<(usize, &str)> = lines
      .iter()
      .enumerate()
      .filter(|(_, line)| line.len() > MIN_LONG_LINE_LENGTH)
      .map(|(i, line)| (i + 1, *line))
      .collect();

    if !long_lines.is_empty() {
      let (line_num, line) = long_lines[0];
      let message = format!(
        "File contains very long lines ({} chars). It might be minified or obfuscated.",
        line.len()
      );

      let id = generate_issue_id(
        self.name(),
        context.file_path.to_str().unwrap_or(""),
        line_num,
        &message,
      );

      issues.push(Issue {
        issue_type: self.name().to_string(),
        line: line_num,
        message,
        severity: Severity::Low,
        code: Some(format!("{}...", &line[..80.min(line.len())])),
        analyzer: Some(self.name().to_string()),
        id: Some(id),
      });
    }

    if context.source.len() > MIN_CODE_LENGTH {
      let whitespace_count = context.source.chars().filter(|c| c.is_whitespace()).count();
      let ratio = whitespace_count as f64 / context.source.len() as f64;

      if ratio < MAX_WHITESPACE_RATIO {
        let message = "File has very low whitespace ratio. It appears to be minified.".to_string();

        let id =
          generate_issue_id(self.name(), context.file_path.to_str().unwrap_or(""), 1, &message);

        issues.push(Issue {
          issue_type: self.name().to_string(),
          line: 1,
          message,
          severity: Severity::Low,
          code: None,
          analyzer: Some(self.name().to_string()),
          id: Some(id),
        });
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
  fn test_detects_long_lines() {
    let analyzer = MinifiedAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Create a line longer than 1000 chars
    let long_line = "a".repeat(1500);
    let source = format!("// normal comment\n{}\n// another comment", long_line);

    let context = FileContext {
      source: &source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("long lines"));
  }

  #[test]
  fn test_detects_low_whitespace() {
    let analyzer = MinifiedAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Create minified-looking code (low whitespace)
    let source = "a".repeat(600); // No whitespace

    let context = FileContext {
      source: &source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("whitespace"));
  }

  #[test]
  fn test_ignores_normal_code() {
    let analyzer = MinifiedAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"
function hello() {
    console.log('Hello, World!');
}

const x = 1;
const y = 2;
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

  #[test]
  fn test_ignores_short_code() {
    let analyzer = MinifiedAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Short code without whitespace shouldn't trigger
    let source = "abc123";

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
