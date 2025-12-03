use std::fs;

use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::util::generate_issue_id;

const NATIVE_DEPS: &[&str] = &[
  "node-gyp",
  "node-pre-gyp",
  "prebuild-install",
  "nan",
  "cmake-js",
  "node-addon-api",
  "napi-rs",
  "neon-cli",
];

pub struct NativeAnalyzer;

#[async_trait]
impl PackageAnalyzer for NativeAnalyzer {
  fn name(&self) -> &'static str {
    "native"
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    let binding_gyp_path = context.path.join("binding.gyp");
    if fs::metadata(&binding_gyp_path).is_ok() {
      let message = "Package contains native code (binding.gyp). Native modules can execute arbitrary code during build.";

      let id = generate_issue_id(self.name(), context.name, 0, message, Some(context.name));

      issues.push(Issue {
        issue_type: self.name().to_string(),
        line: 0,
        message: message.to_string(),
        severity: Severity::Medium,
        code: None,
        analyzer: Some(self.name().to_string()),
        id: Some(id),
        file: Some("binding.gyp".to_string()),
      });
    }

    let cmake_path = context.path.join("CMakeLists.txt");
    if fs::metadata(&cmake_path).is_ok() {
      let message = "Package contains CMakeLists.txt. May build native code during installation.";

      let id = generate_issue_id(self.name(), context.name, 0, message, Some(context.name));

      issues.push(Issue {
        issue_type: self.name().to_string(),
        line: 0,
        message: message.to_string(),
        severity: Severity::Medium,
        code: None,
        analyzer: Some(self.name().to_string()),
        id: Some(id),
        file: Some("CMakeLists.txt".to_string()),
      });
    }

    let deps = context.package_json.get("dependencies");
    let dev_deps = context.package_json.get("devDependencies");

    for native_dep in NATIVE_DEPS {
      let has_dep = deps.and_then(|d| d.get(*native_dep)).is_some()
        || dev_deps.and_then(|d| d.get(*native_dep)).is_some();

      if has_dep {
        let message = format!("Package depends on native build tool: \"{}\".", native_dep);

        let id = generate_issue_id(self.name(), context.name, 0, &message, Some(context.name));

        issues.push(Issue {
          issue_type: self.name().to_string(),
          line: 0,
          message,
          severity: Severity::Medium,
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

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  #[test]
  fn test_analyzer_name() {
    let analyzer = NativeAnalyzer;
    assert_eq!(analyzer.name(), "native");
  }

  #[tokio::test]
  async fn test_detects_native_dependency() {
    let analyzer = NativeAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "dependencies": {
            "node-gyp": "^9.0.0"
        }
    });

    let context = PackageContext {
      name: "test-package",
      version: "1.0.0",
      path: &PathBuf::from("/nonexistent"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("node-gyp"));
  }

  #[tokio::test]
  async fn test_detects_nan_dependency() {
    let analyzer = NativeAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "devDependencies": {
            "nan": "^2.0.0"
        }
    });

    let context = PackageContext {
      name: "test-package",
      version: "1.0.0",
      path: &PathBuf::from("/nonexistent"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert!(!issues.is_empty());
    assert!(issues[0].message.contains("nan"));
  }

  #[tokio::test]
  async fn test_no_issues_for_clean_package() {
    let analyzer = NativeAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "dependencies": {
            "lodash": "^4.0.0"
        }
    });

    let context = PackageContext {
      name: "test-package",
      version: "1.0.0",
      path: &PathBuf::from("/nonexistent"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    // No binding.gyp exists and no native deps
    let native_dep_issues: Vec<_> =
      issues.iter().filter(|i| i.message.contains("native build tool")).collect();
    assert!(native_dep_issues.is_empty());
  }
}
