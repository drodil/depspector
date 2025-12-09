use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseConfig {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub severity: Option<String>,
  #[serde(default)]
  pub allowed_licenses: Vec<String>,
  #[serde(default = "default_risky_licenses")]
  pub risky_licenses: HashMap<String, String>,
}

fn default_risky_licenses() -> HashMap<String, String> {
  let mut map = HashMap::new();
  // Restrictive licenses - High severity
  map.insert("GPL ".to_string(), "high".to_string());
  map.insert("GPL-".to_string(), "high".to_string());
  map.insert("AGPL".to_string(), "high".to_string());
  map.insert("SSPL".to_string(), "high".to_string());
  map.insert("EUPL-1.2".to_string(), "high".to_string());

  // Moderate licenses
  map.insert("MPL".to_string(), "medium".to_string());
  map.insert("CDDL".to_string(), "medium".to_string());
  map.insert("CPAL".to_string(), "medium".to_string());

  map
}

impl Default for LicenseConfig {
  fn default() -> Self {
    Self {
      enabled: None,
      severity: None,
      allowed_licenses: Vec::new(),
      risky_licenses: default_risky_licenses(),
    }
  }
}

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

    let allowed_licenses = &context.config.analyzers.license.allowed_licenses;

    if allowed_licenses.contains(&license_str.to_string()) {
      return issues;
    }

    let license_upper = license_str.to_uppercase();
    let risky_licenses = &context.config.analyzers.license.risky_licenses;

    for (key, severity_str) in risky_licenses {
      if license_upper.contains(&key.to_uppercase()) {
        let severity = match severity_str.to_lowercase().as_str() {
          "critical" => Severity::Critical,
          "high" => Severity::High,
          "medium" | "moderate" => Severity::Medium,
          _ => Severity::Low,
        };

        let message =
          format!("Package uses {} license which is flagged as {}.", license_str, severity_str);

        let package_json_str =
          serde_json::to_string_pretty(&context.package_json).unwrap_or_default();
        let line = crate::util::find_line_in_json(&package_json_str, "license").unwrap_or(0);

        let mut issue = Issue::new(self.name(), message, severity, "package.json")
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

    config.analyzers.license.allowed_licenses.push("GPL-3.0".to_string());

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
