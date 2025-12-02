use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::util::generate_issue_id;

const SUSPICIOUS_LIFECYCLE_EVENTS: &[&str] =
  &["preinstall", "install", "postinstall", "prepublish", "prepare", "prepack", "postpack"];

pub struct ScriptsAnalyzer;

#[async_trait]
impl PackageAnalyzer for ScriptsAnalyzer {
  fn name(&self) -> &'static str {
    "scripts"
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    let scripts = match context.package_json.get("scripts") {
      Some(s) => s,
      None => return issues,
    };

    let scripts_obj = match scripts.as_object() {
      Some(o) => o,
      None => return issues,
    };

    let allowed_scripts = context
      .config
      .get_analyzer_config("scripts")
      .and_then(|c| c.allowed_scripts.clone())
      .unwrap_or_default();

    for event in SUSPICIOUS_LIFECYCLE_EVENTS {
      if let Some(script) = scripts_obj.get(*event) {
        if let Some(script_str) = script.as_str() {
          if allowed_scripts.contains(&event.to_string()) {
            continue;
          }

          let message = format!(
                        "Package uses suspicious lifecycle script: \"{}\". This is a common vector for malware.",
                        event
                    );

          let id = generate_issue_id(self.name(), context.name, 0, &message);

          issues.push(Issue {
            issue_type: self.name().to_string(),
            line: 0,
            message,
            severity: Severity::Medium,
            code: Some(script_str.to_string()),
            analyzer: Some(self.name().to_string()),
            id: Some(id),
            file: None,
          });
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
  fn test_analyzer_name() {
    let analyzer = ScriptsAnalyzer;
    assert_eq!(analyzer.name(), "scripts");
  }

  #[tokio::test]
  async fn test_detects_postinstall() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "postinstall": "node setup.js"
        }
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
    assert!(issues[0].message.contains("postinstall"));
  }

  #[tokio::test]
  async fn test_detects_preinstall() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "preinstall": "echo 'installing'"
        }
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
    assert!(issues[0].message.contains("preinstall"));
  }

  #[tokio::test]
  async fn test_ignores_safe_scripts() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "test": "jest",
            "build": "tsc",
            "start": "node index.js"
        }
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
  async fn test_allowed_scripts() {
    let analyzer = ScriptsAnalyzer;
    let mut config = crate::config::Config::default();

    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.allowed_scripts = Some(vec!["postinstall".to_string()]);
    config.analyzers.insert("scripts".to_string(), analyzer_config);

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "postinstall": "node setup.js"
        }
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
  async fn test_no_scripts() {
    let analyzer = ScriptsAnalyzer;
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
