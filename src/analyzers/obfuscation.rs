use super::{FileAnalyzer, FileContext, Issue, Severity};
use crate::util::generate_issue_id;

pub struct ObfuscationAnalyzer;

const DEFAULT_MIN_STRING_LENGTH: usize = 200;

impl FileAnalyzer for ObfuscationAnalyzer {
  fn name(&self) -> &'static str {
    "obfuscation"
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue> {
    let mut issues = vec![];

    let config = context.config.get_analyzer_config(self.name());
    let min_string_length =
      config.and_then(|c| c.min_string_length).unwrap_or(DEFAULT_MIN_STRING_LENGTH);

    for (line_num, line) in context.source.lines().enumerate() {
      if let Some(long_string) = find_long_string(line, min_string_length) {
        let message = format!(
          "Suspiciously long string detected ({} chars, potential obfuscation)",
          long_string.len()
        );

        let id = generate_issue_id(
          self.name(),
          context.file_path.to_str().unwrap_or(""),
          line_num + 1,
          &message,
        );

        let preview = if long_string.chars().count() > 50 {
          let truncated: String = long_string.chars().take(50).collect();
          format!("{}...", truncated)
        } else {
          long_string.to_string()
        };

        issues.push(Issue {
          issue_type: self.name().to_string(),
          line: line_num + 1,
          message,
          severity: Severity::Low,
          code: Some(preview),
          analyzer: Some(self.name().to_string()),
          id: Some(id),
          file: None,
        });
      }

      if contains_number_array(line, 20) {
        let message = "Large array of numbers detected (potential obfuscated data)".to_string();

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
          severity: Severity::Low,
          code: Some(truncate_line(line, 80)),
          analyzer: Some(self.name().to_string()),
          id: Some(id),
          file: None,
        });
      }
    }

    issues
  }
}

fn find_long_string(line: &str, min_length: usize) -> Option<&str> {
  if line.len() < min_length {
    return None;
  }

  let mut in_string = false;
  let mut quote_char = ' ';
  let mut start = 0;

  for (i, c) in line.char_indices() {
    if !in_string && (c == '"' || c == '\'' || c == '`') {
      in_string = true;
      quote_char = c;
      start = i + 1;
    } else if in_string && c == quote_char {
      let string_content = &line[start..i];
      if string_content.len() >= min_length && !string_content.contains(' ') {
        return Some(string_content);
      }
      in_string = false;
    }
  }

  None
}

fn contains_number_array(line: &str, min_count: usize) -> bool {
  if !line.contains('[') {
    return false;
  }

  // Quick heuristic: if not enough commas, it can't have enough elements
  if line.chars().filter(|&c| c == ',').count() < min_count {
    return false;
  }

  let mut number_count = 0;
  let mut in_array = false;

  for c in line.chars() {
    if c == '[' {
      in_array = true;
      number_count = 0;
    } else if c == ']' {
      if in_array && number_count >= min_count {
        return true;
      }
      in_array = false;
    } else if in_array && c == ',' {
      number_count += 1;
    }
  }

  false
}

fn truncate_line(line: &str, max_len: usize) -> String {
  let trimmed = line.trim();
  if trimmed.chars().count() > max_len {
    let truncated: String = trimmed.chars().take(max_len).collect();
    format!("{}...", truncated)
  } else {
    trimmed.to_string()
  }
}
#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_detects_long_string() {
    let analyzer = ObfuscationAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let long_str = "a".repeat(250);
    let source = format!(r#"const x = "{}";"#, long_str);

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
    assert!(issues[0].message.contains("obfuscation"));
  }

  #[test]
  fn test_ignores_short_strings() {
    let analyzer = ObfuscationAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let source = r#"const x = "hello world";"#;

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
  fn test_ignores_long_strings_with_spaces() {
    let analyzer = ObfuscationAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    // Long string with spaces (like documentation)
    let source = format!(r#"const x = "{}";"#, "this is a long string with many words ".repeat(10));

    let context = FileContext {
      source: &source,
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
  fn test_configurable_threshold() {
    let analyzer = ObfuscationAnalyzer;
    let mut config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.min_string_length = Some(50);
    config.analyzers.insert("obfuscation".to_string(), analyzer_config);

    let source = format!(r#"const x = "{}";"#, "a".repeat(60));

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
  }

  #[test]
  fn test_detects_number_array() {
    let analyzer = ObfuscationAnalyzer;
    let config = crate::config::Config::default();
    let file_path = PathBuf::from("test.js");

    let numbers = (0..30).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let source = format!("const arr = [{}];", numbers);

    let context = FileContext {
      source: &source,
      file_path: &file_path,
      package_name: Some("test-package"),
      package_version: Some("1.0.0"),
      config: &config,
      parsed_ast: None,
    };
    let issues = analyzer.analyze(&context);

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("array of numbers")));
  }
}
