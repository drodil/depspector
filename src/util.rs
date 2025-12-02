use sha2::{Digest, Sha256};

pub fn normalize_path(path: &str) -> String {
  path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}

pub fn get_line(source: &str, line_number: usize) -> String {
  source
    .lines()
    .nth(line_number.saturating_sub(1))
    .map(|s| s.trim().to_string())
    .unwrap_or_default()
}

/// Pre-computed line index for O(1) line lookups.
/// Stores byte offsets for each line start, allowing fast retrieval of any line.
pub struct LineIndex {
  source: String,
  line_starts: Vec<usize>,
}

impl LineIndex {
  pub fn new(source: &str) -> Self {
    let mut line_starts = vec![0];
    for (i, c) in source.char_indices() {
      if c == '\n' {
        line_starts.push(i + 1);
      }
    }
    Self { source: source.to_string(), line_starts }
  }

  pub fn get_line(&self, line_number: usize) -> String {
    if line_number == 0 || line_number > self.line_starts.len() {
      return String::new();
    }

    let start = self.line_starts[line_number - 1];
    let end = if line_number < self.line_starts.len() {
      self.line_starts[line_number].saturating_sub(1)
    } else {
      self.source.len()
    };

    if start >= self.source.len() {
      return String::new();
    }

    self.source[start..end.min(self.source.len())].trim().to_string()
  }
}

pub fn sha256_hash(input: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(input.as_bytes());
  let result = hasher.finalize();
  hex::encode(result)
}

pub fn generate_issue_id(analyzer: &str, file_path: &str, line: usize, message: &str) -> String {
  let input = format!("{}:{}:{}:{}", analyzer, file_path, line, message);
  let hash = sha256_hash(&input);
  hash[..12].to_string()
}

pub fn is_base64_like(s: &str) -> bool {
  if s.len() < 20 {
    return false;
  }

  let base64_chars: Vec<char> =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".chars().collect();

  let matching = s.chars().filter(|c| base64_chars.contains(c)).count();
  let ratio = matching as f64 / s.len() as f64;

  ratio > 0.9 && s.len().is_multiple_of(4)
}

pub fn is_hex_like(s: &str) -> bool {
  if s.len() < 20 || !s.len().is_multiple_of(2) {
    return false;
  }

  s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn calculate_entropy(s: &str) -> f64 {
  if s.is_empty() {
    return 0.0;
  }

  let mut freq = std::collections::HashMap::new();
  for c in s.chars() {
    *freq.entry(c).or_insert(0) += 1;
  }

  let len = s.len() as f64;
  freq
    .values()
    .map(|&count| {
      let p = count as f64 / len;
      -p * p.log2()
    })
    .sum()
}

pub fn is_sensitive_path(path: &str) -> bool {
  let sensitive_patterns = [
    "/etc/passwd",
    "/etc/shadow",
    ".ssh",
    ".aws",
    ".npmrc",
    ".env",
    ".git/config",
    "id_rsa",
    "id_dsa",
    "known_hosts",
    ".bash_history",
    ".zsh_history",
    "/proc/",
    "/sys/",
  ];

  let path_lower = path.to_lowercase();
  sensitive_patterns.iter().any(|p| path_lower.contains(p))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_get_line() {
    let source = "line1\nline2\nline3";
    assert_eq!(get_line(source, 1), "line1");
    assert_eq!(get_line(source, 2), "line2");
    assert_eq!(get_line(source, 3), "line3");
    assert_eq!(get_line(source, 4), "");
  }

  #[test]
  fn test_line_index_basic() {
    let source = "line1\nline2\nline3";
    let index = LineIndex::new(source);
    assert_eq!(index.get_line(1), "line1");
    assert_eq!(index.get_line(2), "line2");
    assert_eq!(index.get_line(3), "line3");
    assert_eq!(index.get_line(4), "");
    assert_eq!(index.get_line(0), "");
  }

  #[test]
  fn test_line_index_with_whitespace() {
    let source = "  indented\n\ttabbed\n  spaced  ";
    let index = LineIndex::new(source);
    assert_eq!(index.get_line(1), "indented");
    assert_eq!(index.get_line(2), "tabbed");
    assert_eq!(index.get_line(3), "spaced");
  }

  #[test]
  fn test_line_index_empty_lines() {
    let source = "first\n\nthird";
    let index = LineIndex::new(source);
    assert_eq!(index.get_line(1), "first");
    assert_eq!(index.get_line(2), "");
    assert_eq!(index.get_line(3), "third");
  }

  #[test]
  fn test_generate_issue_id() {
    let id = generate_issue_id("buffer", "test.js", 10, "test message");
    assert_eq!(id.len(), 12);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
  }

  #[test]
  fn test_is_base64_like() {
    assert!(is_base64_like("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="));
    assert!(!is_base64_like("hello"));
    assert!(!is_base64_like("not base64!!!"));
  }

  #[test]
  fn test_is_hex_like() {
    assert!(is_hex_like("48656c6c6f20576f726c6421"));
    assert!(!is_hex_like("hello"));
    assert!(!is_hex_like("GGGG"));
  }

  #[test]
  fn test_calculate_entropy() {
    // High entropy (random-looking)
    let high = calculate_entropy("aB3$xY7!qW9@mN2#");
    // Low entropy (repetitive)
    let low = calculate_entropy("aaaaaaaaaaaaaaaa");

    assert!(high > low);
  }

  #[test]
  fn test_is_sensitive_path() {
    assert!(is_sensitive_path("/etc/passwd"));
    assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
    assert!(is_sensitive_path(".npmrc"));
    assert!(!is_sensitive_path("/usr/local/lib/node_modules"));
  }
}
