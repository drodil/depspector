use napi::bindgen_prelude::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmConfig {
  #[serde(default = "default_registry")]
  pub registry: String,
  #[serde(default)]
  pub token: Option<String>,
  #[serde(default)]
  pub username: Option<String>,
  #[serde(default)]
  pub password: Option<String>,
}

impl Default for NpmConfig {
  fn default() -> Self {
    Self { registry: default_registry(), token: None, username: None, password: None }
  }
}

fn default_registry() -> String {
  "https://registry.npmjs.org".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzerConfig {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub severity: Option<String>,
  #[serde(default)]
  pub min_buffer_length: Option<usize>,
  #[serde(default)]
  pub hours_since_publish: Option<u64>,
  #[serde(default)]
  pub days_since_previous_publish: Option<u64>,
  #[serde(default)]
  pub whitelisted_users: Option<Vec<String>>,
  #[serde(default)]
  pub min_severity: Option<String>,
  #[serde(default)]
  pub days_since_last_publish: Option<u64>,
  #[serde(default)]
  pub allowed_variables: Option<Vec<String>>,
  #[serde(default)]
  pub allowed_env_vars: Option<Vec<String>>,
  #[serde(default)]
  pub additional_dangerous_paths: Option<Vec<String>>,
  #[serde(default)]
  pub require_repository: Option<bool>,
  #[serde(default)]
  pub require_license: Option<bool>,
  #[serde(default)]
  pub min_string_length: Option<usize>,
  #[serde(default)]
  pub allowed_hosts: Option<Vec<String>>,
  #[serde(default)]
  pub min_obfuscation_score: Option<f64>,
  #[serde(default)]
  pub min_downloads: Option<u64>,
  #[serde(default)]
  pub allowed_scripts: Option<Vec<String>>,
  #[serde(default)]
  pub popular_packages: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
  #[serde(default)]
  pub exclude: Vec<String>,
  #[serde(default)]
  pub ignore_issues: Vec<String>,
  #[serde(default = "default_cache_dir")]
  pub cache_dir: String,
  #[serde(default = "default_report_level")]
  pub report_level: String,
  #[serde(default)]
  pub exit_with_failure_on_level: Option<String>,
  #[serde(default)]
  pub fail_fast: bool,
  #[serde(default)]
  pub npm: NpmConfig,
  #[serde(default)]
  pub analyzers: HashMap<String, AnalyzerConfig>,
}

fn default_cache_dir() -> String {
  std::env::temp_dir().join("depspector-cache").to_string_lossy().to_string()
}

fn default_report_level() -> String {
  "low".to_string()
}

impl Default for Config {
  fn default() -> Self {
    Self {
      exclude: Vec::new(),
      ignore_issues: Vec::new(),
      cache_dir: default_cache_dir(),
      report_level: default_report_level(),
      exit_with_failure_on_level: None,
      fail_fast: false,
      npm: NpmConfig::default(),
      analyzers: HashMap::new(),
    }
  }
}

impl Config {
  pub fn load(config_path: Option<&Path>, cwd: Option<&Path>) -> Result<Self> {
    use napi::Error as NapiError;

    if let Some(path) = config_path {
      if path.exists() {
        let content = fs::read_to_string(path)?;
        return serde_json::from_str(&content)
          .map_err(|e| NapiError::from_reason(format!("Config parse error: {}", e)));
      }
    }

    let default_paths = [".depspectorrc", ".depspectorrc.json", "depspector.config.json"];
    let base_dir = cwd.unwrap_or_else(|| Path::new("."));

    for name in &default_paths {
      let path = base_dir.join(name);
      if path.exists() {
        let content = fs::read_to_string(&path)?;
        return serde_json::from_str(&content)
          .map_err(|e| NapiError::from_reason(format!("Config parse error: {}", e)));
      }
    }

    Ok(Config::default())
  }

  pub fn get_analyzer_config(&self, name: &str) -> Option<&AnalyzerConfig> {
    self.analyzers.get(name)
  }

  pub fn is_analyzer_enabled(&self, name: &str) -> bool {
    self.analyzers.get(name).and_then(|c| c.enabled).unwrap_or(true)
  }

  pub fn get_analyzer_severity(&self, name: &str) -> Option<&str> {
    self.analyzers.get(name).and_then(|c| c.severity.as_deref())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_default_config() {
    let config = Config::default();
    assert!(config.exclude.is_empty());
    assert!(config.ignore_issues.is_empty());
    assert_eq!(config.report_level, "low");
  }

  #[test]
  fn test_analyzer_enabled_default() {
    let config = Config::default();
    assert!(config.is_analyzer_enabled("buffer"));
    assert!(config.is_analyzer_enabled("nonexistent"));
  }

  #[test]
  fn test_parse_config() {
    let json = r#"{
            "exclude": ["test-pkg"],
            "ignoreIssues": ["abc123"],
            "reportLevel": "high",
            "analyzers": {
                "buffer": {
                    "enabled": false,
                    "minBufferLength": 100
                }
            }
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.exclude, vec!["test-pkg"]);
    assert_eq!(config.ignore_issues, vec!["abc123"]);
    assert_eq!(config.report_level, "high");
    assert!(!config.is_analyzer_enabled("buffer"));
  }

  #[test]
  fn test_npm_config_default() {
    let config = Config::default();
    assert_eq!(config.npm.registry, "https://registry.npmjs.org");
    assert!(config.npm.token.is_none());
    assert!(config.npm.username.is_none());
    assert!(config.npm.password.is_none());
  }

  #[test]
  fn test_parse_npm_config() {
    let json = r#"{
            "npm": {
                "registry": "https://custom.registry.com",
                "token": "secret-token"
            }
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.npm.registry, "https://custom.registry.com");
    assert_eq!(config.npm.token, Some("secret-token".to_string()));
  }

  #[test]
  fn test_parse_npm_basic_auth() {
    let json = r#"{
            "npm": {
                "registry": "https://private.registry.com",
                "username": "myuser",
                "password": "mypass"
            }
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.npm.registry, "https://private.registry.com");
    assert_eq!(config.npm.username, Some("myuser".to_string()));
    assert_eq!(config.npm.password, Some("mypass".to_string()));
  }
}
