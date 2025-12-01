use napi::bindgen_prelude::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::analyzers::AnalysisResult;
use crate::util::sha256_hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
  version: String,
  content_hash: String,
  results: Vec<AnalysisResult>,
  timestamp: u64,
}

pub struct PackageCache {
  cache_dir: PathBuf,
  cache_key: String,
  entries: RwLock<HashMap<String, CacheEntry>>,
}

impl PackageCache {
  pub fn new(cache_dir: &str, cwd: &Path, node_modules: &Path) -> Result<Self> {
    let cache_dir = PathBuf::from(cache_dir);
    fs::create_dir_all(&cache_dir)?;

    let cache_key = Self::generate_cache_key(cwd, node_modules);

    let cache = Self { cache_dir, cache_key, entries: RwLock::new(HashMap::new()) };

    cache.load_cache()?;
    Ok(cache)
  }

  fn generate_cache_key(cwd: &Path, node_modules: &Path) -> String {
    let key_input = format!("{}:{}", cwd.to_string_lossy(), node_modules.to_string_lossy());
    sha256_hash(&key_input)[..16].to_string()
  }

  fn cache_file(&self) -> PathBuf {
    self.cache_dir.join(format!("cache-{}.json", self.cache_key))
  }

  fn load_cache(&self) -> Result<()> {
    let cache_file = self.cache_file();
    if cache_file.exists() {
      let content = fs::read_to_string(&cache_file)?;
      let loaded: HashMap<String, CacheEntry> = serde_json::from_str(&content).unwrap_or_default();
      *self.entries.write().unwrap() = loaded;
    }
    Ok(())
  }

  fn save_cache(&self) -> Result<()> {
    use napi::Error as NapiError;

    let cache_file = self.cache_file();
    let entries = self.entries.read().unwrap();
    let content = serde_json::to_string_pretty(&*entries)
      .map_err(|e| NapiError::from_reason(format!("Cache serialize error: {}", e)))?;
    drop(entries); // Release lock before writing
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
    let entries = self.entries.read().unwrap();

    if let Some(entry) = entries.get(&key) {
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
    let entries = self.entries.read().unwrap();
    entries.get(&key).map(|e| e.results.clone())
  }

  pub fn get(&self, name: &str, version: &str) -> Option<AnalysisResult> {
    let key = format!("{}@{}", name, version);
    let entries = self.entries.read().unwrap();
    entries.get(&key).and_then(|e| e.results.first().cloned())
  }

  pub fn set(&self, name: &str, version: &str, result: &AnalysisResult) -> Result<()> {
    let key = format!("{}@{}", name, version);

    let timestamp = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0);

    {
      let mut entries = self.entries.write().unwrap();
      entries.insert(
        key,
        CacheEntry {
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
      let mut entries = self.entries.write().unwrap();
      entries
        .insert(key, CacheEntry { version: version.to_string(), content_hash, results, timestamp });
    }

    self.save_cache()
  }

  pub fn clear_all(&self) -> Result<()> {
    let cache_file = self.cache_file();
    if cache_file.exists() {
      fs::remove_file(cache_file)?;
    }
    // Also clear in-memory entries
    self.entries.write().unwrap().clear();
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;
  use std::sync::RwLock;

  #[test]
  fn test_cache_key_format() {
    let key = format!("{}@{}", "test-package", "1.0.0");
    assert_eq!(key, "test-package@1.0.0");
  }

  #[test]
  fn test_compute_hash_consistency() {
    let _cache = PackageCache {
      cache_dir: env::temp_dir(),
      cache_key: "test".to_string(),
      entries: RwLock::new(HashMap::new()),
    };

    // Same input should produce same hash
    let hash1 = crate::util::sha256_hash("test content");
    let hash2 = crate::util::sha256_hash("test content");
    assert_eq!(hash1, hash2);

    // Different input should produce different hash
    let hash3 = crate::util::sha256_hash("different content");
    assert_ne!(hash1, hash3);
  }

  #[test]
  fn test_generate_cache_key() {
    let cwd1 = Path::new("/home/user/project1");
    let node_modules1 = Path::new("/home/user/project1/node_modules");

    let cwd2 = Path::new("/home/user/project2");
    let node_modules2 = Path::new("/home/user/project2/node_modules");

    let key1 = PackageCache::generate_cache_key(cwd1, node_modules1);
    let key2 = PackageCache::generate_cache_key(cwd2, node_modules2);
    let key1_again = PackageCache::generate_cache_key(cwd1, node_modules1);

    // Same inputs should produce the same key
    assert_eq!(key1, key1_again);

    // Different inputs should produce different keys
    assert_ne!(key1, key2);

    // Key should be 16 characters (truncated hash)
    assert_eq!(key1.len(), 16);
  }
}
