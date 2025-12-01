use crate::config::NpmConfig;
use crate::registry::{PackageMetadata, Registry};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// A package identifier (name, version)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PackageId {
  pub name: String,
  pub version: String,
}

impl PackageId {
  pub fn new(name: &str, version: &str) -> Self {
    Self { name: name.to_string(), version: version.to_string() }
  }

  pub fn cache_key(&self) -> String {
    format!("{}@{}", self.name, self.version)
  }
}

/// CVE/vulnerability information for a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
  pub id: String,
  pub summary: Option<String>,
  pub details: Option<String>,
  pub severity_type: Option<String>,
  pub score: Option<String>,
  pub database_severity: Option<String>,
}

/// OSV batch query request
#[derive(Debug, Serialize)]
struct OSVBatchQuery {
  queries: Vec<OSVSingleQuery>,
}

#[derive(Debug, Serialize)]
struct OSVSingleQuery {
  version: String,
  package: OSVPackage,
}

#[derive(Debug, Serialize)]
struct OSVPackage {
  name: String,
  ecosystem: String,
}

/// OSV batch query response
#[derive(Debug, Deserialize)]
struct OSVBatchResponse {
  results: Vec<OSVBatchResult>,
}

#[derive(Debug, Deserialize)]
struct OSVBatchResult {
  vulns: Option<Vec<OSVVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct OSVVulnerability {
  id: String,
  summary: Option<String>,
  details: Option<String>,
  severity: Option<Vec<OSVSeverity>>,
  database_specific: Option<DatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
struct OSVSeverity {
  #[serde(rename = "type")]
  severity_type: String,
  score: String,
}

#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
  severity: Option<String>,
}

/// Pre-fetched data store for all packages
pub struct PrefetchedData {
  /// Registry metadata keyed by package name (contains all versions)
  metadata: Arc<RwLock<HashMap<String, PackageMetadata>>>,
  /// CVE/vulnerability info keyed by "name@version"
  vulnerabilities: Arc<RwLock<HashMap<String, Vec<VulnerabilityInfo>>>>,
  /// Registry for fallback requests
  registry: Registry,
  /// Cache directory for fallback requests
  cache_dir: String,
}

impl PrefetchedData {
  pub fn new(registry: Registry, cache_dir: String) -> Self {
    Self {
      metadata: Arc::new(RwLock::new(HashMap::new())),
      vulnerabilities: Arc::new(RwLock::new(HashMap::new())),
      registry,
      cache_dir,
    }
  }

  pub async fn get_metadata(&self, name: &str, version: &str) -> Option<PackageMetadata> {
    {
      let cache = self.metadata.read().await;
      if let Some(meta) = cache.get(name) {
        return Some(meta.clone());
      }
    }

    match self.registry.get_package_cached(name, version, &self.cache_dir).await {
      Ok(meta) => {
        let mut cache = self.metadata.write().await;
        cache.insert(name.to_string(), meta.clone());
        Some(meta)
      }
      Err(e) => {
        log::debug!("[PREFETCH] Failed to fetch metadata for {}: {}", name, e);
        None
      }
    }
  }

  pub async fn get_vulnerabilities(
    &self,
    name: &str,
    version: &str,
  ) -> Option<Vec<VulnerabilityInfo>> {
    let key = format!("{}@{}", name, version);
    let cache = self.vulnerabilities.read().await;
    cache.get(&key).cloned()
  }
}

/// Prefetcher for bulk network operations
pub struct Prefetcher {
  registry: Registry,
  client: Client,
  npm_config: NpmConfig,
}

impl Prefetcher {
  pub fn new(npm_config: &NpmConfig) -> Self {
    let client = Client::builder()
      .pool_max_idle_per_host(20)
      .pool_idle_timeout(std::time::Duration::from_secs(90))
      .timeout(std::time::Duration::from_secs(30))
      .build()
      .unwrap_or_else(|_| Client::new());

    Self { registry: Registry::with_config(npm_config), client, npm_config: npm_config.clone() }
  }

  pub async fn prefetch(
    &self,
    packages: &[PackageId],
    cache_dir: &str,
    concurrency: usize,
  ) -> PrefetchedData {
    let data = PrefetchedData::new(Registry::with_config(&self.npm_config), cache_dir.to_string());

    let packages_with_highest_version: Vec<(String, String)> = {
      let mut by_name: HashMap<String, Vec<&str>> = HashMap::new();
      for pkg in packages {
        by_name.entry(pkg.name.clone()).or_default().push(&pkg.version);
      }

      by_name
        .into_iter()
        .map(|(name, versions)| {
          // Find highest semver version
          let highest = versions
            .iter()
            .filter_map(|v| semver::Version::parse(v).ok().map(|sv| (*v, sv)))
            .max_by(|(_, a), (_, b)| a.cmp(b))
            .map(|(v, _)| v.to_string())
            .unwrap_or_else(|| versions[0].to_string());
          (name, highest)
        })
        .collect()
    };

    log::debug!(
      "[PREFETCH] Starting prefetch for {} unique package names",
      packages_with_highest_version.len()
    );

    let prefetch_start = Instant::now();
    let ((), ()) = tokio::join!(
      self.prefetch_metadata(&packages_with_highest_version, cache_dir, concurrency, &data),
      self.prefetch_cves(packages, &data)
    );
    log::debug!(
      "[PREFETCH] Parallel prefetch took {:?} (metadata: {} unique packages, CVE: {} packages)",
      prefetch_start.elapsed(),
      packages_with_highest_version.len(),
      packages.len()
    );

    data
  }

  async fn prefetch_metadata(
    &self,
    packages: &[(String, String)], // (name, highest_version)
    cache_dir: &str,
    concurrency: usize,
    data: &PrefetchedData,
  ) {
    let cache_dir_owned = cache_dir.to_string();
    let results: Vec<_> = stream::iter(packages.iter().cloned())
      .map(|(name, version)| {
        let cache_dir = cache_dir_owned.clone();
        let registry = &self.registry;
        async move {
          match registry.get_package_cached(&name, &version, &cache_dir).await {
            Ok(meta) => Some((name, meta)),
            Err(e) => {
              log::debug!("[PREFETCH] Failed to fetch metadata for {}: {}", name, e);
              None
            }
          }
        }
      })
      .buffer_unordered(concurrency)
      .collect()
      .await;

    let mut metadata_map = data.metadata.write().await;
    for result in results.into_iter().flatten() {
      let (name, meta) = result;
      metadata_map.insert(name, meta);
    }
  }

  async fn prefetch_cves(&self, packages: &[PackageId], data: &PrefetchedData) {
    const BATCH_SIZE: usize = 500;

    for chunk in packages.chunks(BATCH_SIZE) {
      let queries: Vec<OSVSingleQuery> = chunk
        .iter()
        .map(|p| OSVSingleQuery {
          version: p.version.clone(),
          package: OSVPackage { name: p.name.clone(), ecosystem: "npm".to_string() },
        })
        .collect();

      let batch_query = OSVBatchQuery { queries };

      let response = match self
        .client
        .post("https://api.osv.dev/v1/querybatch")
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(60))
        .json(&batch_query)
        .send()
        .await
      {
        Ok(r) => r,
        Err(e) => {
          log::debug!("[PREFETCH] CVE batch request failed: {}", e);
          continue;
        }
      };

      let batch_response: OSVBatchResponse = match response.json().await {
        Ok(r) => r,
        Err(e) => {
          log::debug!("[PREFETCH] Failed to parse CVE batch response: {}", e);
          continue;
        }
      };

      let mut vuln_map = data.vulnerabilities.write().await;
      for (pkg, result) in chunk.iter().zip(batch_response.results.iter()) {
        let key = pkg.cache_key();
        let vulns = result
          .vulns
          .as_ref()
          .map(|v| {
            v.iter()
              .map(|vuln| VulnerabilityInfo {
                id: vuln.id.clone(),
                summary: vuln.summary.clone(),
                details: vuln.details.clone(),
                severity_type: vuln
                  .severity
                  .as_ref()
                  .and_then(|s| s.first())
                  .map(|s| s.severity_type.clone()),
                score: vuln.severity.as_ref().and_then(|s| s.first()).map(|s| s.score.clone()),
                database_severity: vuln.database_specific.as_ref().and_then(|d| d.severity.clone()),
              })
              .collect()
          })
          .unwrap_or_default();
        vuln_map.insert(key, vulns);
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_package_id_cache_key() {
    let id = PackageId::new("lodash", "4.17.21");
    assert_eq!(id.cache_key(), "lodash@4.17.21");
  }

  #[tokio::test]
  async fn test_prefetched_data_new() {
    let npm_config = NpmConfig::default();
    let data = PrefetchedData::new(Registry::with_config(&npm_config), ".cache".to_string());
    // Note: get_metadata now does fallback, so we just test the structure exists
    assert!(data.get_vulnerabilities("test", "1.0.0").await.is_none());
  }
}
