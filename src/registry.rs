use napi::bindgen_prelude::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::config::NpmConfig;

const DEFAULT_REGISTRY_URL: &str = "https://registry.npmjs.org";

lazy_static::lazy_static! {
  /// Cache key format: "name@version" for version-specific caching
  static ref GLOBAL_METADATA_CACHE: Arc<RwLock<HashMap<String, PackageMetadata>>> = Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct PackageVersion {
  pub version: String,
  #[serde(default)]
  pub dist: Option<PackageDist>,
  #[serde(default, rename = "_npmUser")]
  pub npm_user: Option<NpmUser>,
  #[serde(default)]
  pub deprecated: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct PackageDist {
  pub tarball: String,
  #[serde(default)]
  pub shasum: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct NpmUser {
  pub name: String,
  #[serde(default)]
  pub email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct PackageMetadata {
  pub name: String,
  #[serde(default)]
  pub description: Option<String>,
  #[serde(default)]
  pub versions: std::collections::HashMap<String, PackageVersion>,
  #[serde(default)]
  pub time: std::collections::HashMap<String, String>,
  #[serde(default)]
  pub maintainers: Vec<NpmUser>,
  #[serde(rename = "dist-tags", default)]
  pub dist_tags: std::collections::HashMap<String, String>,
}

pub struct Registry {
  client: Client,
  base_url: String,
  auth_header: Option<String>,
}

impl Registry {
  fn build_client() -> Client {
    Client::builder()
      .pool_max_idle_per_host(10)
      .pool_idle_timeout(std::time::Duration::from_secs(1))
      .timeout(std::time::Duration::from_secs(30))
      .build()
      .unwrap_or_else(|_| Client::new())
  }

  pub fn new() -> Self {
    Self {
      client: Self::build_client(),
      base_url: DEFAULT_REGISTRY_URL.to_string(),
      auth_header: None,
    }
  }

  pub fn with_config(config: &NpmConfig) -> Self {
    let base_url = config.registry.trim_end_matches('/').to_string();
    let auth_header = Self::build_auth_header(config);

    Self { client: Self::build_client(), base_url, auth_header }
  }

  fn build_auth_header(config: &NpmConfig) -> Option<String> {
    if let Some(ref token) = config.token {
      return Some(format!("Bearer {}", token));
    }

    if let (Some(ref username), Some(ref password)) = (&config.username, &config.password) {
      use base64::{engine::general_purpose::STANDARD, Engine};
      let credentials = format!("{}:{}", username, password);
      let encoded = STANDARD.encode(credentials.as_bytes());
      return Some(format!("Basic {}", encoded));
    }

    None
  }

  pub async fn get_package(&self, name: &str) -> Result<PackageMetadata> {
    let url = format!("{}/{}", self.base_url, name);
    let max_retries = 3;
    let mut last_error = None;

    for attempt in 0..=max_retries {
      if attempt > 0 {
        let delay = std::time::Duration::from_millis(100 * 2_u64.pow(attempt - 1));
        tokio::time::sleep(delay).await;
      }

      let mut request = self.client.get(&url).header("Accept", "application/json");

      if let Some(ref auth) = self.auth_header {
        request = request.header("Authorization", auth);
      }

      match request.send().await {
        Ok(response) => {
          if response.status().is_success() {
            return response
              .json::<PackageMetadata>()
              .await
              .map_err(|e| napi::Error::from_reason(format!("Failed to parse metadata: {}", e)));
          } else if response.status().as_u16() == 404 {
            return Err(napi::Error::from_reason(format!(
              "Package not found: {} (status {})",
              name,
              response.status()
            )));
          } else {
            let status = response.status();
            last_error = Some(napi::Error::from_reason(format!(
              "Registry request failed with status: {}",
              status
            )));
            if status.as_u16() < 500 && status.as_u16() != 429 {
              break;
            }
          }
        }
        Err(e) => {
          last_error = Some(napi::Error::from_reason(format!("Registry request failed: {}", e)));
        }
      }
    }

    Err(
      last_error
        .unwrap_or_else(|| napi::Error::from_reason("Registry request failed after retries")),
    )
  }

  fn ensure_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
      fs::create_dir_all(parent)?;
    }
    Ok(())
  }

  fn metadata_cache_path(cache_dir: &str, name: &str, version: &str) -> PathBuf {
    Path::new(cache_dir)
      .join("registry")
      .join("metadata")
      .join(format!("{}@{}.json", name, version))
  }

  fn cache_key(name: &str, version: &str) -> String {
    format!("{}@{}", name, version)
  }

  pub async fn get_package_cached(
    &self,
    name: &str,
    version: &str,
    cache_dir: &str,
  ) -> Result<PackageMetadata> {
    let cache_key = Self::cache_key(name, version);

    {
      let cache = GLOBAL_METADATA_CACHE.read().unwrap();
      if let Some(meta) = cache.get(&cache_key) {
        return Ok(meta.clone());
      }
    }

    let path = Self::metadata_cache_path(cache_dir, name, version);
    if path.exists() {
      if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(meta) = serde_json::from_str::<PackageMetadata>(&content) {
          {
            let mut cache = GLOBAL_METADATA_CACHE.write().unwrap();
            cache.insert(cache_key.clone(), meta.clone());
          }
          return Ok(meta);
        }
      }
    }

    let meta = self.get_package(name).await?;

    {
      let mut cache = GLOBAL_METADATA_CACHE.write().unwrap();
      cache.insert(cache_key, meta.clone());
    }

    if let Ok(content) = serde_json::to_string(&meta) {
      let _ = Self::ensure_dir(&path);
      let _ = fs::write(path, content);
    }
    Ok(meta)
  }

  pub fn clear_memory_cache() {
    let mut cache = GLOBAL_METADATA_CACHE.write().unwrap();
    cache.clear();
  }
}

impl Default for Registry {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_with_custom_registry() {
    let config = NpmConfig {
      registry: "https://custom.registry.com".to_string(),
      token: None,
      username: None,
      password: None,
    };
    let registry = Registry::with_config(&config);
    assert_eq!(registry.base_url, "https://custom.registry.com");
    assert!(registry.auth_header.is_none());
  }

  #[test]
  fn test_with_token_auth() {
    let config = NpmConfig {
      registry: "https://registry.npmjs.org".to_string(),
      token: Some("test-token".to_string()),
      username: None,
      password: None,
    };
    let registry = Registry::with_config(&config);
    assert_eq!(registry.auth_header, Some("Bearer test-token".to_string()));
  }

  #[test]
  fn test_with_basic_auth() {
    let config = NpmConfig {
      registry: "https://registry.npmjs.org".to_string(),
      token: None,
      username: Some("user".to_string()),
      password: Some("pass".to_string()),
    };
    let registry = Registry::with_config(&config);
    assert!(registry.auth_header.is_some());
    assert!(registry.auth_header.as_ref().unwrap().starts_with("Basic "));
  }

  #[test]
  fn test_token_takes_precedence_over_basic() {
    let config = NpmConfig {
      registry: "https://registry.npmjs.org".to_string(),
      token: Some("test-token".to_string()),
      username: Some("user".to_string()),
      password: Some("pass".to_string()),
    };
    let registry = Registry::with_config(&config);
    assert_eq!(registry.auth_header, Some("Bearer test-token".to_string()));
  }
}
