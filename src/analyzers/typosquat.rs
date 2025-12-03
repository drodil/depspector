use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::util::generate_issue_id;

const POPULAR_PACKAGES: &[&str] = &[
  "react",
  "react-dom",
  "vue",
  "angular",
  "express",
  "lodash",
  "moment",
  "axios",
  "tslib",
  "commander",
  "chalk",
  "debug",
  "inquirer",
  "fs-extra",
  "body-parser",
  "cors",
  "dotenv",
  "uuid",
  "aws-sdk",
  "webpack",
  "eslint",
  "prettier",
  "typescript",
  "jest",
  "mocha",
  "chai",
  "supertest",
  "nodemon",
  "rimraf",
  "glob",
  "async",
  "underscore",
  "request",
  "bluebird",
  "yargs",
  "minimist",
  "colors",
  "mkdirp",
  "semver",
  "qs",
  "ws",
  "socket.io",
  "mongoose",
  "sequelize",
  "redis",
  "pg",
  "mysql",
  "next",
  "nuxt",
  "gatsby",
  "electron",
];

pub struct TyposquatAnalyzer;

#[async_trait]
impl PackageAnalyzer for TyposquatAnalyzer {
  fn name(&self) -> &'static str {
    "typosquat"
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];
    let pkg_name = context.name;

    let config = context.config.get_analyzer_config("typosquat");
    let additional_packages: Vec<String> =
      config.and_then(|c| c.popular_packages.clone()).unwrap_or_default();

    if !pkg_name.is_ascii() {
      let message =
        "Package name contains non-ASCII characters (potential homoglyph attack)".to_string();

      let id = generate_issue_id(self.name(), pkg_name, 0, &message, Some(pkg_name));

      issues.push(Issue {
        issue_type: self.name().to_string(),
        line: 0,
        message,
        severity: Severity::High,
        code: None,
        analyzer: Some(self.name().to_string()),
        id: Some(id),
        file: None,
      });
    }

    let mut packages_to_check: Vec<&str> = POPULAR_PACKAGES.to_vec();
    for pkg in &additional_packages {
      packages_to_check.push(pkg.as_str());
    }

    for popular in packages_to_check {
      if pkg_name == popular {
        continue;
      }

      let distance = levenshtein(pkg_name, popular);
      let max_len = pkg_name.len().max(popular.len());
      let similarity = 1.0 - (distance as f64 / max_len as f64);

      if distance <= 2 && similarity > 0.8 {
        let message = format!(
          "Package name '{}' is very similar to popular package '{}' (Levenshtein distance: {})",
          pkg_name, popular, distance
        );

        let id = generate_issue_id(self.name(), pkg_name, 0, &message, Some(pkg_name));

        issues.push(Issue {
          issue_type: self.name().to_string(),
          line: 0,
          message,
          severity: Severity::High,
          code: None,
          analyzer: Some(self.name().to_string()),
          id: Some(id),
          file: None,
        });
      }
    }

    issues
  }
}

#[allow(clippy::needless_range_loop)]
fn levenshtein(a: &str, b: &str) -> usize {
  let a_chars: Vec<char> = a.chars().collect();
  let b_chars: Vec<char> = b.chars().collect();

  let a_len = a_chars.len();
  let b_len = b_chars.len();

  if a_len == 0 {
    return b_len;
  }
  if b_len == 0 {
    return a_len;
  }

  let mut matrix: Vec<Vec<usize>> = vec![vec![0; a_len + 1]; b_len + 1];

  for i in 0..=b_len {
    matrix[i][0] = i;
  }
  for j in 0..=a_len {
    matrix[0][j] = j;
  }

  for i in 1..=b_len {
    for j in 1..=a_len {
      let cost = if b_chars[i - 1] == a_chars[j - 1] { 0 } else { 1 };

      matrix[i][j] =
        (matrix[i - 1][j - 1] + cost).min(matrix[i][j - 1] + 1).min(matrix[i - 1][j] + 1);
    }
  }

  matrix[b_len][a_len]
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_analyzer_name() {
    let analyzer = TyposquatAnalyzer;
    assert_eq!(analyzer.name(), "typosquat");
  }

  #[test]
  fn test_levenshtein() {
    assert_eq!(levenshtein("react", "react"), 0);
    assert_eq!(levenshtein("react", "raect"), 2);
    assert_eq!(levenshtein("lodash", "1odash"), 1);
    assert_eq!(levenshtein("express", "expres"), 1);
  }

  #[tokio::test]
  async fn test_detects_typosquat() {
    let analyzer = TyposquatAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "reactt"
    });

    let context = PackageContext {
      name: "reactt",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("react"));
  }

  #[tokio::test]
  async fn test_detects_lodash_typosquat() {
    let analyzer = TyposquatAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "1odash"  // l replaced with 1
    });

    let context = PackageContext {
      name: "1odash",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("lodash"));
  }

  #[tokio::test]
  async fn test_detects_homoglyph() {
    let analyzer = TyposquatAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "rеact"
    });

    let context = PackageContext {
      name: "rеact",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.message.contains("non-ASCII")));
  }

  #[tokio::test]
  async fn test_ignores_legitimate_packages() {
    let analyzer = TyposquatAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "my-awesome-package"
    });

    let context = PackageContext {
      name: "my-awesome-package",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(issues.is_empty());
  }

  #[tokio::test]
  async fn test_exact_match_not_flagged() {
    let analyzer = TyposquatAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "react"
    });

    let context = PackageContext {
      name: "react",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(issues.is_empty());
  }
}
