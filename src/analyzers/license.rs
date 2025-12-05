use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};

const RESTRICTIVE_LICENSES: &[&str] =
  &["GPL", "AGPL", "GPLV2", "GPLV3", "GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL", "EUPL-1.2"];

const MODERATE_LICENSES: &[&str] = &["MPL", "MPL-2.0", "CDDL", "CPAL"];

pub struct LicenseAnalyzer;

#[async_trait]
impl PackageAnalyzer for LicenseAnalyzer {
  fn name(&self) -> &'static str {
    "license"
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    let license = match context.package_json.get("license") {
      Some(l) => l,
      None => return issues,
    };

    let license_str = match license.as_str() {
      Some(s) => s,
      None => {
        if let Some(obj) = license.as_object() {
          if let Some(license_type) = obj.get("type") {
            if let Some(type_str) = license_type.as_str() {
              type_str
            } else {
              return issues;
            }
          } else {
            return issues;
          }
        } else {
          return issues;
        }
      }
    };

    let license_config = context.config.get_analyzer_config("license");
    let allowed_licenses: Vec<String> =
      license_config.and_then(|c| c.allowed_licenses.clone()).unwrap_or_default();

    if allowed_licenses.contains(&license_str.to_string()) {
      return issues;
    }

    let license_upper = license_str.to_uppercase();

    for restrictive in RESTRICTIVE_LICENSES {
      if license_upper.contains(restrictive) {
        let message = format!(
          "Package uses {} license which requires derivative works to be published under the same license.",
          license_str
        );

        let package_json_str =
          serde_json::to_string_pretty(&context.package_json).unwrap_or_default();
        let line = crate::util::find_line_in_json(&package_json_str, "license").unwrap_or(0);

        let mut issue = Issue::new(self.name(), message, Severity::High, "package.json")
          .with_package_name(context.name);
        if line > 0 {
          issue = issue.with_line(line);
        }
        issues.push(issue);
        return issues;
      }
    }

    for moderate in MODERATE_LICENSES {
      if license_upper.contains(moderate) {
        let message =
          format!("Package uses {} license which requires source code attribution.", license_str);

        // Use pretty print to preserve line structure for line number detection
        let package_json_str =
          serde_json::to_string_pretty(&context.package_json).unwrap_or_default();
        let line = crate::util::find_line_in_json(&package_json_str, "license").unwrap_or(0);

        let mut issue = Issue::new(self.name(), message, Severity::Medium, "package.json")
          .with_package_name(context.name);
        if line > 0 {
          issue = issue.with_line(line);
        }
        issues.push(issue);
        return issues;
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
    let analyzer = LicenseAnalyzer;
    assert_eq!(analyzer.name(), "license");
  }

  #[tokio::test]
  async fn test_detects_gpl_license() {
    let analyzer = LicenseAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
      "name": "test-package",
      "license": "GPL-3.0"
    });

    let context = PackageContext {
      name: "test-package",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].analyzer, "license");
    assert_eq!(issues[0].severity, Severity::High);
  }

  #[tokio::test]
  async fn test_detects_agpl_license() {
    let analyzer = LicenseAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
      "name": "test-package",
      "license": "AGPL-3.0"
    });

    let context = PackageContext {
      name: "test-package",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::High);
  }

  #[tokio::test]
  async fn test_detects_mpl_license() {
    let analyzer = LicenseAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
      "name": "test-package",
      "license": "MPL-2.0"
    });

    let context = PackageContext {
      name: "test-package",
      version: "1.0.0",
      path: &PathBuf::from("/test"),
      package_json: &package_json,
      config: &config,
      prefetched: None,
    };

    let issues = analyzer.analyze(&context).await;

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].analyzer, "license");
    assert_eq!(issues[0].severity, Severity::Medium);
  }

  #[tokio::test]
  async fn test_allows_mit_license() {
    let analyzer = LicenseAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
      "name": "test-package",
      "license": "MIT"
    });

    let context = PackageContext {
      name: "test-package",
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
  async fn test_allows_apache_license() {
    let analyzer = LicenseAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
      "name": "test-package",
      "license": "Apache-2.0"
    });

    let context = PackageContext {
      name: "test-package",
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
  async fn test_allows_configured_license() {
    let analyzer = LicenseAnalyzer;
    let mut config = crate::config::Config::default();

    let analyzer_config = crate::config::AnalyzerConfig {
      allowed_licenses: Some(vec!["GPL-3.0".to_string()]),
      ..Default::default()
    };
    config.analyzers.insert("license".to_string(), analyzer_config);

    let package_json = serde_json::json!({
      "name": "test-package",
      "license": "GPL-3.0"
    });

    let context = PackageContext {
      name: "test-package",
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
  async fn test_handles_missing_license() {
    let analyzer = LicenseAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
      "name": "test-package"
    });

    let context = PackageContext {
      name: "test-package",
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
