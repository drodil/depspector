use napi::bindgen_prelude::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::analyzers::AnalysisResult;
use crate::util::sha256_hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageCacheEntry {
  version: String,
  content_hash: String,
  results: Vec<AnalysisResult>,
  timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCacheEntry {
  pub is_false_positive: bool,
  pub reason: Option<String>,
  pub confidence: Option<f32>,
  pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CacheData {
  #[serde(default)]
  packages: HashMap<String, PackageCacheEntry>,
  #[serde(default)]
  ai: HashMap<String, AiCacheEntry>,
}

pub struct PackageCache {
  cache_dir: PathBuf,
  cache_key: String,
  data: RwLock<CacheData>,
}

impl PackageCache {
  pub fn new(cache_dir: &str, cwd: &Path, node_modules: &Path) -> Result<Self> {
    let cache_dir = PathBuf::from(cache_dir);
    fs::create_dir_all(&cache_dir)?;

    let cache_key = Self::generate_cache_key(cwd, node_modules);

    let cache = Self { cache_dir, cache_key, data: RwLock::new(CacheData::default()) };

    cache.load_cache()?;
    Ok(cache)
  }

  fn generate_cache_key(cwd: &Path, node_modules: &Path) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let key_input =
      format!("v{}:{}:{}", version, cwd.to_string_lossy(), node_modules.to_string_lossy());
    sha256_hash(&key_input)[..16].to_string()
  }

  fn cache_file(&self) -> PathBuf {
    self.cache_dir.join(format!("cache-{}.json", self.cache_key))
  }

  fn load_cache(&self) -> Result<()> {
    let cache_file = self.cache_file();
    if cache_file.exists() {
      let content = fs::read_to_string(&cache_file)?;
      let loaded: CacheData = serde_json::from_str(&content).unwrap_or_default();
      *self.data.write().unwrap() = loaded;
    }
    Ok(())
  }

  fn save_cache(&self) -> Result<()> {
    use napi::Error as NapiError;

    let cache_file = self.cache_file();
    let data = self.data.read().unwrap();
    let content = serde_json::to_string_pretty(&*data)
      .map_err(|e| NapiError::from_reason(format!("Cache serialize error: {}", e)))?;
    drop(data); // Release lock before writing
    fs::write(cache_file, content)?;
    Ok(())
  }

  fn compute_hash(&self, pkg_dir: &Path) -> String {
    let mut files_content = String::new();

    if let Ok(entries) = fs::read_dir(pkg_dir) {
      let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).collect();
      paths.sort_by_key(|e| e.path());

      for entry in paths {
        let path = entry.path();
        if path.is_file() {
          if let Some(ext) = path.extension() {
            if ext == "js" || ext == "mjs" || ext == "ts" {
              if let Ok(content) = fs::read_to_string(&path) {
                files_content.push_str(&content);
              }
            }
          }
        }
      }
    }

    sha256_hash(&files_content)
  }

  pub fn has_changed(&self, name: &str, version: &str, pkg_dir: &Path) -> bool {
    let key = format!("{}@{}", name, version);
    let data = self.data.read().unwrap();

    if let Some(entry) = data.packages.get(&key) {
      if entry.version != version {
        return true;
      }

      let current_hash = self.compute_hash(pkg_dir);
      current_hash != entry.content_hash
    } else {
      true
    }
  }

  pub fn get_results(&self, name: &str, version: &str) -> Option<Vec<AnalysisResult>> {
    let key = format!("{}@{}", name, version);
    let data = self.data.read().unwrap();
    data.packages.get(&key).map(|e| e.results.clone())
  }

  pub fn get(&self, name: &str, version: &str) -> Option<AnalysisResult> {
    let key = format!("{}@{}", name, version);
    let data = self.data.read().unwrap();
    data.packages.get(&key).and_then(|e| e.results.first().cloned())
  }

  pub fn get_if_fresh(
    &self,
    name: &str,
    version: &str,
    max_age_seconds: Option<u64>,
  ) -> Option<AnalysisResult> {
    let key = format!("{}@{}", name, version);
    let data = self.data.read().unwrap();
    if let Some(entry) = data.packages.get(&key) {
      if let Some(max_age) = max_age_seconds {
        let now = std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .map(|d| d.as_secs())
          .unwrap_or(0);
        if now.saturating_sub(entry.timestamp) > max_age {
          return None;
        }
      }
      return entry.results.first().cloned();
    }
    None
  }

  pub fn set(&self, name: &str, version: &str, result: &AnalysisResult) -> Result<()> {
    let key = format!("{}@{}", name, version);

    let timestamp = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0);

    {
      let mut data = self.data.write().unwrap();
      data.packages.insert(
        key,
        PackageCacheEntry {
          version: version.to_string(),
          content_hash: String::new(),
          results: vec![result.clone()],
          timestamp,
        },
      );
    }

    self.save_cache()
  }

  pub fn update_entry(
    &self,
    name: &str,
    version: &str,
    pkg_dir: &Path,
    results: Vec<AnalysisResult>,
  ) -> Result<()> {
    let key = format!("{}@{}", name, version);
    let content_hash = self.compute_hash(pkg_dir);

    let timestamp = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0);

    {
      let mut data = self.data.write().unwrap();
      data.packages.insert(
        key,
        PackageCacheEntry { version: version.to_string(), content_hash, results, timestamp },
      );
    }

    self.save_cache()
  }

  pub fn clear_all(&self) -> Result<()> {
    // Remove all cache files for any keys in the cache directory
    if let Ok(dir_entries) = fs::read_dir(&self.cache_dir) {
      for entry in dir_entries.flatten() {
        let path = entry.path();
        if path.is_file() {
          if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
            if fname.starts_with("cache-") && fname.ends_with(".json") {
              let _ = fs::remove_file(&path);
            }
          }
        }
      }
    }
    self.data.write().unwrap().packages.clear();
    self.data.write().unwrap().ai.clear();
    Ok(())
  }

  pub fn get_ai(&self, issue_id: &str) -> Option<AiCacheEntry> {
    let data = self.data.read().unwrap();
    data.ai.get(issue_id).cloned()
  }

  pub fn set_ai(
    &self,
    issue_id: &str,
    is_false_positive: bool,
    reason: Option<String>,
    confidence: Option<f32>,
  ) -> Result<()> {
    let timestamp = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0);

    {
      let mut data = self.data.write().unwrap();
      data.ai.insert(
        issue_id.to_string(),
        AiCacheEntry { is_false_positive, reason, confidence, timestamp },
      );
    }

    self.save_cache()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;

  #[test]
  fn test_cache_key_format() {
    let key = format!("{}@{}", "test-package", "1.0.0");
    assert_eq!(key, "test-package@1.0.0");
  }

  #[test]
  fn test_ai_cache_integration() {
    let cache_dir = env::temp_dir().join("depspector_test_unified_cache");
    let _ = fs::remove_dir_all(&cache_dir);
    let cwd = Path::new(".");
    let node_modules = Path::new("node_modules");

    let cache = PackageCache::new(cache_dir.to_str().unwrap(), cwd, node_modules).unwrap();

    cache.set_ai("ISSUE-1", true, Some("safe".to_string()), Some(0.95)).unwrap();
    let entry = cache.get_ai("ISSUE-1").unwrap();
    assert!(entry.is_false_positive);
    assert_eq!(entry.reason, Some("safe".to_string()));

    let cache2 = PackageCache::new(cache_dir.to_str().unwrap(), cwd, node_modules).unwrap();
    let entry2 = cache2.get_ai("ISSUE-1").unwrap();
    assert!(entry2.is_false_positive);

    let _ = fs::remove_dir_all(&cache_dir);
  }
}
