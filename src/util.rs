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

pub fn extract_relative_path(file_path: &str) -> String {
  let normalized = file_path.replace('\\', "/");

  // Look for node_modules with or without leading slash
  let nm_pattern = if normalized.contains("/node_modules/") {
    "/node_modules/"
  } else if normalized.starts_with("node_modules/") {
    "node_modules/"
  } else {
    ""
  };

  if !nm_pattern.is_empty() {
    let last_nm_idx = normalized.rfind(nm_pattern).unwrap();
    let after_nm = &normalized[last_nm_idx + nm_pattern.len()..];

    let pkg_end = if after_nm.starts_with('@') {
      after_nm.find('/').and_then(|first| after_nm[first + 1..].find('/').map(|s| first + 1 + s))
    } else {
      after_nm.find('/')
    };

    if let Some(idx) = pkg_end {
      return after_nm[idx + 1..].to_string();
    }
  }

  normalized.rsplit('/').next().unwrap_or(&normalized).to_string()
}

pub fn normalize_line_bucket(line: usize) -> usize {
  (line / 20) * 20
}

pub fn generate_issue_id(
  analyzer: &str,
  file_path: &str,
  line: usize,
  message: &str,
  package_name: Option<&str>,
) -> String {
  let pkg_prefix = package_name
    .map(|name| {
      let clean = name.trim_start_matches('@').replace('/', "-");
      let prefix: String = clean.chars().take(8).collect();
      prefix
    })
    .unwrap_or_else(|| "unknown".to_string());

  let relative_path = extract_relative_path(file_path);

  let normalized_relative = relative_path
    .replace("dist-node/", "")
    .replace("dist-src/", "")
    .replace("dist-web/", "")
    .replace("dist-cjs/", "")
    .replace("dist-esm/", "")
    .replace("dist-types/", "")
    .replace("dist/", "")
    .replace("lib/", "")
    .replace("build/", "")
    .replace("cjs/", "")
    .replace("esm/", "")
    .replace("umd/", "");

  let message_sig: String =
    message.split_whitespace().take(4).collect::<Vec<_>>().join(" ").chars().take(40).collect();

  let line_bucket = normalize_line_bucket(line);
  let hash_input = format!("{}:{}:{}", normalized_relative, line_bucket, message_sig);
  let hash = sha256_hash(&hash_input);

  let id = format!("{}-{}-{}", pkg_prefix, analyzer, &hash[..6]);
  let cleaned = id.replace("--", "-");
  cleaned.to_uppercase()
}

pub fn matches_ignore_id(issue_id: &str, ignore_id: &str) -> bool {
  if issue_id == ignore_id {
    return true;
  }

  if issue_id.contains('-') && ignore_id.contains('-') {
    let issue_parts: Vec<_> = issue_id.rsplitn(2, '-').collect();
    let ignore_parts: Vec<_> = ignore_id.rsplitn(2, '-').collect();

    if issue_parts.len() == 2 && ignore_parts.len() == 2 {
      return issue_parts[1] == ignore_parts[1];
    }
  }

  false
}

pub fn find_line_in_json(content: &str, key: &str) -> Option<usize> {
  let search_pattern = format!("\"{}\":", key);
  let search_lower = search_pattern.to_lowercase();

  for (line_num, line) in content.lines().enumerate() {
    if line.to_lowercase().contains(&search_lower) {
      return Some(line_num + 1);
    }
  }
  None
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
    let id = generate_issue_id("buffer", "test.js", 10, "test message", Some("my-package"));
    // New format: {pkg_prefix}-{analyzer}-{hash} in uppercase
    assert!(id.starts_with("MY-PACKA-BUFFER-"));
    assert_eq!(id.len(), 22); // 8 + 1 + 6 + 1 + 6 = 22
  }

  #[test]
  fn test_generate_issue_id_scoped_package() {
    let id =
      generate_issue_id("secrets", "dist/index.js", 50, "Private key found", Some("@octokit/app"));
    // Scoped package: @octokit/app -> octokit-app (scope removed, / replaced, uppercase)
    assert!(id.starts_with("OCTOKIT-"));
    assert!(id.contains("-SECRETS-"));
    // Should not have double dashes
    assert!(!id.contains("--"));
  }

  #[test]
  fn test_generate_issue_id_line_tolerance() {
    // Lines within the same 20-line bucket should generate the same ID
    let id1 = generate_issue_id("eval", "src/file.js", 65, "eval detected", Some("pkg"));
    let id2 = generate_issue_id("eval", "src/file.js", 70, "eval detected", Some("pkg"));
    let id3 = generate_issue_id("eval", "src/file.js", 79, "eval detected", Some("pkg"));

    // All in bucket 60-79
    assert_eq!(id1, id2);
    assert_eq!(id2, id3);

    // Line 80 is in a different bucket (80-99)
    let id4 = generate_issue_id("eval", "src/file.js", 80, "eval detected", Some("pkg"));
    assert_ne!(id3, id4);
  }

  #[test]
  fn test_generate_issue_id_dist_variants() {
    // Same issue in different dist folders should have the same ID
    let id1 = generate_issue_id(
      "secrets",
      "node_modules/@octokit/auth-app/dist-node/index.js",
      67,
      "Potential Private Key",
      Some("@octokit/auth-app"),
    );
    let id2 = generate_issue_id(
      "secrets",
      "node_modules/@octokit/auth-app/dist-src/index.js",
      65,
      "Potential Private Key",
      Some("@octokit/auth-app"),
    );
    let id3 = generate_issue_id(
      "secrets",
      "node_modules/@octokit/auth-app/dist-web/index.js",
      71,
      "Potential Private Key",
      Some("@octokit/auth-app"),
    );

    // All three should have the same ID since they're the same issue type
    // in the same package, same file, with lines in the same bucket (60-79)
    assert_eq!(id1, id2);
    assert_eq!(id2, id3);
  }

  #[test]
  fn test_extract_relative_path() {
    // Extracts path after package name
    assert_eq!(extract_relative_path("node_modules/@scope/pkg/dist/index.js"), "dist/index.js");
    assert_eq!(
      extract_relative_path("node_modules/@scope/pkg/node_modules/@other/dep/src/file.js"),
      "src/file.js"
    );
    // Returns filename when no node_modules structure
    assert_eq!(extract_relative_path("simple.js"), "simple.js");
    // Returns filename when path has no package structure
    assert_eq!(extract_relative_path("src/dist/index.js"), "index.js");
  }

  #[test]
  fn test_matches_ignore_id() {
    // Exact match
    assert!(matches_ignore_id("pkg-secrets-abc123", "pkg-secrets-abc123"));

    // Prefix match (ignores hash differences)
    assert!(matches_ignore_id("pkg-secrets-abc123", "pkg-secrets-def456"));

    // Different analyzer - no match
    assert!(!matches_ignore_id("pkg-secrets-abc123", "pkg-eval-abc123"));

    // Different package - no match
    assert!(!matches_ignore_id("pkg1-secrets-abc123", "pkg2-secrets-abc123"));
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

  #[test]
  fn test_find_line_in_json_found() {
    let content = r#"{
  "name": "test",
  "scripts": {
    "postinstall": "node setup.js"
  }
}"#;
    let line = find_line_in_json(content, "scripts");
    assert_eq!(line, Some(3));
  }

  #[test]
  fn test_find_line_in_json_not_found() {
    let content = r#"{"name": "test"}"#;
    let line = find_line_in_json(content, "nonexistent");
    assert_eq!(line, None);
  }

  #[test]
  fn test_find_line_in_json_case_insensitive() {
    let content = r#"{"Scripts": {"test": "value"}}"#;
    let line = find_line_in_json(content, "Scripts");
    assert_eq!(line, Some(1));
  }
}
