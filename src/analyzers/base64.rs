use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
  static ref BASE64_REGEX: Regex =
    Regex::new(r#"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"#).unwrap();
}

pub struct Base64Analyzer;

const DEFAULT_MIN_LENGTH: usize = 1000;

impl FileAnalyzer for Base64Analyzer {
  fn name(&self) -> &'static str {
    "base64"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    let config = context.config.get_analyzer_config(self.name());
    let min_length = config.and_then(|c| c.min_buffer_length).unwrap_or(DEFAULT_MIN_LENGTH);

    let mut current_start = 0;
    let mut in_potential_base64 = false;

    let chars: Vec<(usize, char)> = context.source.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
      let (idx, c) = chars[i];

      let is_b64_char = c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=';

      if is_b64_char {
        if !in_potential_base64 {
          current_start = idx;
          in_potential_base64 = true;
        }
      } else {
        if in_potential_base64 {
          let len = idx - current_start;
          if len >= min_length {
            report_issue(&mut issues, context, current_start, len, self.name());
          }
          in_potential_base64 = false;
        }
      }
      i += 1;
    }

    // Check end of file
    if in_potential_base64 {
      let last_idx = chars.last().map(|(idx, _)| *idx).unwrap_or(0) + 1;
      let len = last_idx - current_start;
      if len >= min_length {
        report_issue(&mut issues, context, current_start, len, self.name());
      }
    }

    issues
  }
}

fn report_issue(
  issues: &mut Vec<Issue>,
  context: &FileContext,
  start_idx: usize,
  len: usize,
  analyzer_name: &str,
) {
  let line_num = context.source[..start_idx].lines().count();
  let message = format!("Large Base64 blob detected ({} characters)", len);

  let id = generate_issue_id(
    analyzer_name,
    context.file_path.to_str().unwrap_or(""),
    line_num,
    &message,
    context.package_name,
  );

  let snippet = if len > 50 {
    format!("{}...", &context.source[start_idx..start_idx + 50])
  } else {
    context.source[start_idx..start_idx + len].to_string()
  };

  issues.push(Issue {
    issue_type: analyzer_name.to_string(),
    line: line_num,
    message,
    severity: Severity::Low,
    code: Some(snippet),
    analyzer: Some(analyzer_name.to_string()),
    id: Some(id),
    file: None,
  });
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_large_base64() {
    let analyzer = Base64Analyzer;
    let mut config = crate::config::Config::default();

    // Set low threshold for testing
    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.min_buffer_length = Some(10);
    config.analyzers.insert("base64".to_string(), analyzer_config);

    let file_path = PathBuf::from("test.js");
    let b64_str = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZyBmb3IgQmFzZTY0";
    let source = format!("const data = '{}';", b64_str);

    let context = FileContext {
      source: &source,
      file_path: &file_path,
      package_name: Some("test-pkg"),
      package_version: None,
      config: &config,
      parsed_ast: None,
    };

    let issues = analyzer.analyze(&context);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("Large Base64 blob"));
  }

  #[test]
  fn test_ignores_short_strings() {
    let analyzer = Base64Analyzer;
    let config = crate::config::Config::default();

    let file_path = PathBuf::from("test.js");
    let b64_str = "SGVsbG8=";
    let source = format!("const data = '{}';", b64_str);

    let context = FileContext {
      source: &source,
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
