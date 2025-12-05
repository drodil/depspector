use async_trait::async_trait;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::benchmark::BenchmarkCollector;
use crate::cache::PackageCache;
use crate::config::Config;
use crate::prefetch::PrefetchedData;
use crate::util::normalize_path;

pub mod base64;
pub mod buffer;
pub mod dynamic;
pub mod env;
pub mod eval;
pub mod fs;
pub mod ip;
pub mod metadata;
pub mod minified;
pub mod network;
pub mod obfuscation;
pub mod pollution;
pub mod process;
pub mod secrets;

pub mod cooldown;
pub mod cve;
pub mod deprecated;
pub mod dormant;
pub mod native;
pub mod reputation;
pub mod scripts;
pub mod typosquat;

pub use base64::Base64Analyzer;
pub use buffer::BufferAnalyzer;
pub use cooldown::CooldownAnalyzer;
pub use cve::CVEAnalyzer;
pub use deprecated::DeprecatedAnalyzer;
pub use dormant::DormantAnalyzer;
pub use dynamic::DynamicAnalyzer;
pub use env::EnvAnalyzer;
pub use eval::EvalAnalyzer;
pub use fs::FsAnalyzer;
pub use ip::IpAnalyzer;
pub use metadata::MetadataAnalyzer;
pub use minified::MinifiedAnalyzer;
pub use native::NativeAnalyzer;
pub use network::NetworkAnalyzer;
pub use obfuscation::ObfuscationAnalyzer;
pub use pollution::PollutionAnalyzer;
pub use process::ProcessAnalyzer;
pub use reputation::ReputationAnalyzer;
pub use scripts::ScriptsAnalyzer;
pub use secrets::SecretsAnalyzer;
pub use typosquat::TyposquatAnalyzer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
  Low,
  Medium,
  High,
  Critical,
}

// Re-export dependency types from the dependencies module
pub use crate::dependencies::{DependencyGraph, DependencyType, PackageInfo};

impl Severity {
  pub fn as_str(&self) -> &'static str {
    match self {
      Severity::Low => "low",
      Severity::Medium => "medium",
      Severity::High => "high",
      Severity::Critical => "critical",
    }
  }
}

impl std::str::FromStr for Severity {
  type Err = ();

  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    Ok(match s.to_lowercase().as_str() {
      "critical" => Severity::Critical,
      "high" => Severity::High,
      "medium" => Severity::Medium,
      _ => Severity::Low,
    })
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
  #[serde(rename = "type")]
  pub issue_type: String,
  pub line: usize,
  pub message: String,
  pub severity: Severity,
  #[serde(default)]
  pub code: Option<String>,
  #[serde(default)]
  pub analyzer: Option<String>,
  #[serde(default)]
  pub id: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub file: Option<String>,
}

const CRITICAL_PENALTY: f64 = 15.0;
const HIGH_PENALTY: f64 = 8.0;
const MEDIUM_PENALTY: f64 = 3.0;
const LOW_PENALTY: f64 = 1.0;

fn calculate_penalty_with_diminishing_returns(count: usize, base_penalty: f64) -> f64 {
  if count == 0 {
    return 0.0;
  }
  let scaling_factor = 3.0;
  (1.0 + count as f64).ln() * base_penalty * scaling_factor
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustScore {
  pub score: f64,
  pub critical_count: usize,
  pub high_count: usize,
  pub medium_count: usize,
  pub low_count: usize,
}

impl TrustScore {
  pub fn calculate(issues: &[Issue]) -> Self {
    let critical_count = issues.iter().filter(|i| i.severity == Severity::Critical).count();
    let high_count = issues.iter().filter(|i| i.severity == Severity::High).count();
    let medium_count = issues.iter().filter(|i| i.severity == Severity::Medium).count();
    let low_count = issues.iter().filter(|i| i.severity == Severity::Low).count();

    let penalty = calculate_penalty_with_diminishing_returns(critical_count, CRITICAL_PENALTY)
      + calculate_penalty_with_diminishing_returns(high_count, HIGH_PENALTY)
      + calculate_penalty_with_diminishing_returns(medium_count, MEDIUM_PENALTY)
      + calculate_penalty_with_diminishing_returns(low_count, LOW_PENALTY);

    let score = (100.0 - penalty).max(0.0);

    Self { score, critical_count, high_count, medium_count, low_count }
  }

  pub fn trust_level(&self) -> &'static str {
    match self.score as u32 {
      90..=100 => "High",
      70..=89 => "Moderate",
      50..=69 => "Low",
      _ => "Very Low",
    }
  }
}

impl Default for TrustScore {
  fn default() -> Self {
    Self { score: 100.0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0 }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
  #[serde(rename = "file")]
  pub package_path: String,

  #[serde(default)]
  pub package: Option<String>,

  pub issues: Vec<Issue>,

  #[serde(default)]
  pub trust_score: TrustScore,

  #[serde(default)]
  pub dependency_type: DependencyType,

  #[serde(default)]
  pub is_transient: bool,

  #[serde(default)]
  pub is_from_cache: bool,
}

impl AnalysisResult {
  pub fn new(package_path: &str) -> Self {
    Self {
      package_path: package_path.to_string(),
      package: None,
      issues: vec![],
      trust_score: TrustScore::default(),
      dependency_type: DependencyType::Unknown,
      is_transient: false,
      is_from_cache: false,
    }
  }

  pub fn with_package(package_path: &str, package: &str) -> Self {
    Self {
      package_path: package_path.to_string(),
      package: Some(package.to_string()),
      issues: vec![],
      trust_score: TrustScore::default(),
      dependency_type: DependencyType::Unknown,
      is_transient: false,
      is_from_cache: false,
    }
  }
}

/// Main analysis context shared across all analysis operations.
/// This replaces multiple parameter lists with a single unified context.
pub struct AnalyzeContext<'a> {
  pub node_modules_path: &'a Path,
  pub config: &'a Config,
  pub cache: Option<&'a PackageCache>,
  pub ignore_issues: &'a [String],
  pub fail_fast: bool,
  pub concurrency: usize,
  pub offline: bool,
  pub prefetched: Option<Arc<PrefetchedData>>,
  pub benchmark: Option<BenchmarkCollector>,
  pub dependency_graph: &'a DependencyGraph,
  pub ignored_ids: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl<'a> AnalyzeContext<'a> {
  #[allow(clippy::too_many_arguments)]
  pub fn new(
    node_modules_path: &'a Path,
    config: &'a Config,
    cache: Option<&'a PackageCache>,
    ignore_issues: &'a [String],
    fail_fast: bool,
    concurrency: Option<usize>,
    offline: bool,
    dependency_graph: &'a DependencyGraph,
  ) -> Self {
    let concurrency = concurrency
      .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8));

    Self {
      node_modules_path,
      config,
      cache,
      ignore_issues,
      fail_fast,
      concurrency,
      offline,
      prefetched: None,
      benchmark: None,
      dependency_graph,
      ignored_ids: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
    }
  }

  pub fn with_prefetched(mut self, prefetched: Arc<PrefetchedData>) -> Self {
    self.prefetched = Some(prefetched);
    self
  }

  pub fn with_benchmark(mut self, benchmark: Option<BenchmarkCollector>) -> Self {
    self.benchmark = benchmark;
    self
  }
}

/// Context for file-level analyzers
pub struct FileContext<'a> {
  pub source: &'a str,
  pub file_path: &'a Path,
  pub package_name: Option<&'a str>,
  pub package_version: Option<&'a str>,
  pub config: &'a Config,
  pub parsed_ast: Option<&'a crate::ast::ParsedAst>,
}

pub trait FileAnalyzer: Send + Sync {
  fn name(&self) -> &'static str;

  fn requires_network(&self) -> bool {
    false
  }

  fn uses_ast(&self) -> bool {
    false
  }

  fn analyze(&self, context: &FileContext) -> Vec<Issue>;
}

#[async_trait]
pub trait PackageAnalyzer: Send + Sync {
  fn name(&self) -> &'static str;

  fn requires_network(&self) -> bool {
    false
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue>;
}

/// Context for package-level analyzers
pub struct PackageContext<'a> {
  pub name: &'a str,
  pub version: &'a str,
  pub path: &'a Path,
  pub package_json: &'a serde_json::Value,
  pub config: &'a Config,
  pub prefetched: Option<Arc<PrefetchedData>>,
}

pub struct Analyzer {
  file_analyzers: Vec<Box<dyn FileAnalyzer>>,
  package_analyzers: Vec<Box<dyn PackageAnalyzer>>,
  offline: bool,
  active_analyzers: Vec<String>,
}

impl Analyzer {
  pub fn new(config: &Config, offline: bool, only_analyzers: Option<&[String]>) -> Self {
    let mut file_analyzers: Vec<Box<dyn FileAnalyzer>> = vec![];
    let mut package_analyzers: Vec<Box<dyn PackageAnalyzer>> = vec![];
    let mut active_analyzers: Vec<String> = vec![];

    let should_include = |name: &str| -> bool {
      match only_analyzers {
        Some(filter) if !filter.is_empty() => filter.iter().any(|f| f.eq_ignore_ascii_case(name)),
        _ => config.is_analyzer_enabled(name),
      }
    };

    if should_include("base64") {
      file_analyzers.push(Box::new(Base64Analyzer));
      active_analyzers.push("base64".to_string());
    }
    if should_include("buffer") {
      file_analyzers.push(Box::new(BufferAnalyzer));
      active_analyzers.push("buffer".to_string());
    }
    if should_include("dynamic") {
      file_analyzers.push(Box::new(DynamicAnalyzer));
      active_analyzers.push("dynamic".to_string());
    }
    if should_include("env") {
      file_analyzers.push(Box::new(EnvAnalyzer));
      active_analyzers.push("env".to_string());
    }
    if should_include("eval") {
      file_analyzers.push(Box::new(EvalAnalyzer));
      active_analyzers.push("eval".to_string());
    }
    if should_include("fs") {
      file_analyzers.push(Box::new(FsAnalyzer));
      active_analyzers.push("fs".to_string());
    }
    if should_include("ip") {
      file_analyzers.push(Box::new(IpAnalyzer));
      active_analyzers.push("ip".to_string());
    }
    if should_include("metadata") {
      file_analyzers.push(Box::new(MetadataAnalyzer));
      active_analyzers.push("metadata".to_string());
    }
    if should_include("minified") {
      file_analyzers.push(Box::new(MinifiedAnalyzer));
      active_analyzers.push("minified".to_string());
    }
    if should_include("network") {
      file_analyzers.push(Box::new(NetworkAnalyzer));
      active_analyzers.push("network".to_string());
    }
    if should_include("obfuscation") {
      file_analyzers.push(Box::new(ObfuscationAnalyzer));
      active_analyzers.push("obfuscation".to_string());
    }
    if should_include("pollution") {
      file_analyzers.push(Box::new(PollutionAnalyzer));
      active_analyzers.push("pollution".to_string());
    }
    if should_include("process") {
      file_analyzers.push(Box::new(ProcessAnalyzer));
      active_analyzers.push("process".to_string());
    }
    if should_include("secrets") {
      file_analyzers.push(Box::new(SecretsAnalyzer));
      active_analyzers.push("secrets".to_string());
    }

    if should_include("native") {
      package_analyzers.push(Box::new(NativeAnalyzer));
      active_analyzers.push("native".to_string());
    }
    if should_include("scripts") {
      package_analyzers.push(Box::new(ScriptsAnalyzer));
      active_analyzers.push("scripts".to_string());
    }
    if should_include("typosquat") {
      package_analyzers.push(Box::new(TyposquatAnalyzer));
      active_analyzers.push("typosquat".to_string());
    }

    if !offline {
      if should_include("cooldown") {
        package_analyzers.push(Box::new(CooldownAnalyzer::new()));
        active_analyzers.push("cooldown".to_string());
      }
      if should_include("cve") {
        package_analyzers.push(Box::new(CVEAnalyzer::new()));
        active_analyzers.push("cve".to_string());
      }
      if should_include("deprecated") {
        package_analyzers.push(Box::new(DeprecatedAnalyzer::new()));
        active_analyzers.push("deprecated".to_string());
      }
      if should_include("dormant") {
        package_analyzers.push(Box::new(DormantAnalyzer::new()));
        active_analyzers.push("dormant".to_string());
      }
      if should_include("reputation") {
        package_analyzers.push(Box::new(ReputationAnalyzer::new()));
        active_analyzers.push("reputation".to_string());
      }
    }

    Self { file_analyzers, package_analyzers, offline, active_analyzers }
  }

  pub fn analyze_file(&self, source: &str, file_path: &Path, config: &Config) -> Vec<Issue> {
    self.analyze_file_with_benchmark(source, file_path, config, None)
  }

  pub fn analyze_file_with_benchmark(
    &self,
    source: &str,
    file_path: &Path,
    config: &Config,
    benchmark: Option<&BenchmarkCollector>,
  ) -> Vec<Issue> {
    self.analyze_file_with_package(source, file_path, config, benchmark, None)
  }

  fn analyze_file_with_package(
    &self,
    source: &str,
    file_path: &Path,
    config: &Config,
    benchmark: Option<&BenchmarkCollector>,
    package_name: Option<&str>,
  ) -> Vec<Issue> {
    let file_size = source.len();
    let max_file_size = config.max_file_size;

    let needs_ast = file_size <= max_file_size && self.file_analyzers.iter().any(|a| a.uses_ast());

    let parsed_ast = if needs_ast {
      let ast_start = std::time::Instant::now();
      let result = crate::ast::ParsedAst::parse_with_timeout(source, config.ast_timeout_ms);
      if let Some(b) = benchmark {
        if result.is_some() {
          b.record_ast_parse(&file_path.to_string_lossy(), ast_start.elapsed(), file_size);
        }
      }
      result
    } else {
      None
    };

    let context = FileContext {
      source,
      file_path,
      package_name,
      package_version: None,
      config,
      parsed_ast: parsed_ast.as_ref(),
    };

    self
      .file_analyzers
      .iter()
      .filter(|a| {
        if a.uses_ast() && file_size > max_file_size {
          log::debug!(
            "Skipping AST analyzer '{}' for large file: {} ({} bytes > {} limit)",
            a.name(),
            file_path.display(),
            file_size,
            max_file_size
          );
          return false;
        }
        true
      })
      .flat_map(|a| {
        let start = std::time::Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.analyze(&context)));
        match result {
          Ok(issues) => {
            if let Some(b) = benchmark {
              b.record_analyzer(a.name(), start.elapsed(), issues.len());
            }
            apply_severity_override(issues, a.name(), config)
          }
          Err(_) => {
            log::warn!("Analyzer '{}' panicked on file: {}", a.name(), file_path.display());
            Vec::new()
          }
        }
      })
      .collect()
  }

  pub async fn analyze_package(&self, pkg_ctx: &PackageContext<'_>) -> Vec<Issue> {
    self.analyze_package_with_benchmark(pkg_ctx, None, false).await
  }

  pub async fn analyze_package_with_benchmark(
    &self,
    pkg_ctx: &PackageContext<'_>,
    benchmark: Option<&BenchmarkCollector>,
    is_local: bool,
  ) -> Vec<Issue> {
    use futures::future::join_all;

    let futures: Vec<_> = self
      .package_analyzers
      .iter()
      .filter(|analyzer| {
        if is_local && analyzer.requires_network() {
          return false;
        }
        true
      })
      .map(|analyzer| {
        let name = analyzer.name();
        async move {
          let start = std::time::Instant::now();
          let issues = analyzer.analyze(pkg_ctx).await;
          let duration = start.elapsed();
          (name, issues, duration)
        }
      })
      .collect();

    let results = join_all(futures).await;

    results
      .into_iter()
      .flat_map(|(name, issues, duration)| {
        if let Some(b) = benchmark {
          b.record_analyzer(name, duration, issues.len());
        }
        apply_severity_override(issues, name, pkg_ctx.config)
      })
      .collect()
  }

  pub fn is_offline(&self) -> bool {
    self.offline
  }

  pub fn file_analyzer_count(&self) -> usize {
    self.file_analyzers.len()
  }

  pub fn package_analyzer_count(&self) -> usize {
    self.package_analyzers.len()
  }

  pub async fn analyze_packages(
    &self,
    ctx: &AnalyzeContext<'_>,
  ) -> napi::Result<Vec<AnalysisResult>> {
    use futures::stream::{self, StreamExt};

    let packages = ctx.dependency_graph.discovered_packages();

    if let Some(ref b) = ctx.benchmark {
      b.add_packages(packages.len());
    }

    let discovery_start = std::time::Instant::now();
    let (mut results, work_items) = self.check_cache_for_packages(packages, ctx);
    if let Some(ref b) = ctx.benchmark {
      b.record_discovery_time(discovery_start.elapsed());
    }

    let prefetch_start = std::time::Instant::now();
    let prefetched = self.prefetch_data(&work_items, ctx).await;
    if let Some(ref b) = ctx.benchmark {
      b.record_prefetch_time(prefetch_start.elapsed());
    }

    let mut analyzed: Vec<AnalysisResult> = stream::iter(work_items)
      .map(|wi| self.analyze_single_package(wi, ctx, prefetched.clone()))
      .buffer_unordered(std::cmp::max(50, ctx.concurrency))
      .collect()
      .await;

    results.append(&mut analyzed);

    if ctx.fail_fast && results.iter().any(|r| !r.issues.is_empty()) {
      return Ok(results.into_iter().take(1).collect());
    }
    Ok(results)
  }

  fn check_cache_for_packages(
    &self,
    packages: &[PackageInfo],
    ctx: &AnalyzeContext<'_>,
  ) -> (Vec<AnalysisResult>, Vec<WorkItem>) {
    use rayon::prelude::*;

    let cached_results = std::sync::Mutex::new(Vec::<AnalysisResult>::new());
    let work_items = std::sync::Mutex::new(Vec::<WorkItem>::new());

    packages.par_iter().for_each(|pkg_info| {
      if let Some(cache) = ctx.cache {
        let max_age = ctx.config.cache_max_age_seconds;
        if let Some(cached) = cache.get_if_fresh(&pkg_info.name, &pkg_info.version, max_age) {
          let filtered_issues: Vec<_> = cached
            .issues
            .iter()
            .filter(|issue| {
              self.active_analyzers.iter().any(|a| a.eq_ignore_ascii_case(&issue.issue_type))
            })
            .cloned()
            .collect();

          let cached_analyzer_types: std::collections::HashSet<_> =
            filtered_issues.iter().map(|i| i.issue_type.to_lowercase()).collect();

          let missing_analyzers: Vec<_> = self
            .active_analyzers
            .iter()
            .filter(|a| !cached_analyzer_types.contains(&a.to_lowercase()))
            .collect();

          if missing_analyzers.is_empty() {
            let mut result = cached.clone();
            result.issues = filtered_issues;
            result.is_from_cache = true;
            cached_results.lock().unwrap().push(result);
            return;
          }
        }
      }

      work_items.lock().unwrap().push(WorkItem {
        name: pkg_info.name.clone(),
        version: pkg_info.version.clone(),
        pkg_path: pkg_info.path.clone(),
        package_json: pkg_info.package_json.clone(),
        dependency_type: pkg_info.dependency_type,
        is_transient: pkg_info.is_transient,
        is_root: pkg_info.is_root,
        is_local: pkg_info.is_local,
      });
    });

    (cached_results.into_inner().unwrap(), work_items.into_inner().unwrap())
  }

  async fn prefetch_data(
    &self,
    work_items: &[WorkItem],
    ctx: &AnalyzeContext<'_>,
  ) -> Option<Arc<PrefetchedData>> {
    if self.offline {
      return None;
    }

    let package_ids: Vec<crate::prefetch::PackageId> =
      work_items.iter().map(|wi| crate::prefetch::PackageId::new(&wi.name, &wi.version)).collect();

    let prefetcher = crate::prefetch::Prefetcher::new(&ctx.config.npm);
    let data = prefetcher.prefetch(&package_ids, &ctx.config.cache_dir, ctx.concurrency).await;
    Some(Arc::new(data))
  }

  async fn analyze_single_package(
    &self,
    wi: WorkItem,
    ctx: &AnalyzeContext<'_>,
    prefetched: Option<Arc<PrefetchedData>>,
  ) -> AnalysisResult {
    let pkg_path_clone = wi.pkg_path.clone();
    let is_root = wi.is_root;
    let is_local = wi.is_local;

    let workspace_paths: Vec<PathBuf> = ctx
      .dependency_graph
      .discovered_packages()
      .iter()
      .filter(|p| p.dependency_type == DependencyType::Local)
      .map(|p| p.path.clone())
      .collect();

    let pkg_ctx = PackageContext {
      name: &wi.name,
      version: &wi.version,
      path: &wi.pkg_path,
      package_json: &wi.package_json,
      config: ctx.config,
      prefetched,
    };

    let benchmark = ctx.benchmark.as_ref();
    let (mut package_issues, js_entries) = tokio::join!(
      self.analyze_package_with_benchmark(&pkg_ctx, benchmark, is_local),
      Self::discover_js_files(&pkg_path_clone, is_root, &workspace_paths, ctx.config)
    );

    // Set absolute file path for package-level issues
    for issue in &mut package_issues {
      if issue.file.is_none() {
        let pkg_json_path = wi.pkg_path.join("package.json");
        issue.file = Some(normalize_path(&pkg_json_path.to_string_lossy()));
      }
    }

    if let Some(ref b) = ctx.benchmark {
      b.add_files(js_entries.len());
    }

    let file_issues = self.analyze_files_with_benchmark(&js_entries, ctx, Some(&wi.name));

    let mut all_issues = package_issues;
    all_issues.extend(file_issues);

    let mut seen_ids = std::collections::HashSet::new();
    all_issues.retain(|issue| {
      if let Some(id) = &issue.id {
        if ctx.ignore_issues.contains(id) {
          if let Ok(mut set) = ctx.ignored_ids.lock() {
            set.insert(id.clone());
          }
          return false;
        }
        seen_ids.insert(id.clone())
      } else {
        true
      }
    });

    let trust_score = TrustScore::calculate(&all_issues);

    let result = AnalysisResult {
      package_path: normalize_path(&wi.pkg_path.to_string_lossy()),
      package: Some(wi.name.clone()),
      issues: all_issues,
      trust_score,
      dependency_type: wi.dependency_type,
      is_transient: wi.is_transient,
      is_from_cache: false,
    };

    if let Some(cache) = ctx.cache {
      let _ = cache.update_entry(&wi.name, &wi.version, &wi.pkg_path, vec![result.clone()]);
    }

    result
  }

  async fn discover_js_files(
    pkg_path: &Path,
    is_root: bool,
    workspace_paths: &[PathBuf],
    config: &Config,
  ) -> Vec<PathBuf> {
    use walkdir::WalkDir;

    WalkDir::new(pkg_path)
      .follow_links(false)
      .into_iter()
      .filter_entry(|e| {
        if e.file_type().is_dir() {
          let dir_path = e.path();

          if is_root {
            for ws_path in workspace_paths {
              if ws_path != pkg_path && dir_path == *ws_path {
                return false;
              }
            }
          }

          if let Some(dir_name) = e.file_name().to_str() {
            if is_root && dir_name == "node_modules" {
              return false;
            }

            if matches!(
              dir_name,
              ".bin"
                | "test"
                | "tests"
                | "__tests__"
                | "e2e-test"
                | "example"
                | "examples"
                | "dist"
                | "build"
                | "dist-types"
                | ".yarn"
            ) || config.exclude.iter().any(|e| e == dir_name)
            {
              return false;
            }
          }
        }
        true
      })
      .filter_map(|e| e.ok())
      .filter(|e| {
        if e.file_type().is_symlink() {
          return false;
        }

        let rel_path = e.path().strip_prefix(pkg_path).unwrap_or(e.path());
        let rel_path_str = normalize_path(&rel_path.to_string_lossy());
        if config.exclude_paths.iter().any(|p| rel_path_str.contains(p)) {
          return false;
        }

        let fname = e.file_name().to_string_lossy();
        if fname.ends_with(".d.ts") {
          return false;
        }
        if !config.include_tests && is_test_file(&fname) {
          return false;
        }
        fname.ends_with(".js")
          || fname.ends_with(".mjs")
          || fname.ends_with(".cjs")
          || fname.ends_with(".ts")
      })
      .map(|e| e.path().to_path_buf())
      .collect()
  }

  fn analyze_files_with_benchmark(
    &self,
    js_entries: &[PathBuf],
    ctx: &AnalyzeContext<'_>,
    package_name: Option<&str>,
  ) -> Vec<Issue> {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let total_bytes = AtomicUsize::new(0);
    let total_read_time = std::sync::Mutex::new(std::time::Duration::ZERO);

    let issues: Vec<Issue> = js_entries
      .par_iter()
      .filter_map(|js_path| {
        let read_start = std::time::Instant::now();
        let source = match fs::read_to_string(js_path) {
          Ok(s) => s,
          Err(_) => return None,
        };
        let read_duration = read_start.elapsed();

        if ctx.benchmark.is_some() {
          total_bytes.fetch_add(source.len(), Ordering::Relaxed);
          if let Ok(mut t) = total_read_time.lock() {
            *t += read_duration;
          }
        }

        let mut file_issues = self.analyze_file_with_package(
          &source,
          js_path,
          ctx.config,
          ctx.benchmark.as_ref(),
          package_name,
        );
        let file_path_str = normalize_path(&js_path.to_string_lossy());
        for issue in &mut file_issues {
          issue.file = Some(file_path_str.clone());
        }
        file_issues.retain(|i| {
          if let Some(id) = &i.id {
            if ctx.ignore_issues.contains(id) {
              if let Ok(mut set) = ctx.ignored_ids.lock() {
                set.insert(id.clone());
              }
              return false;
            }
          }
          true
        });
        Some(file_issues)
      })
      .flatten()
      .collect();

    if let Some(ref b) = ctx.benchmark {
      b.add_bytes(total_bytes.load(Ordering::Relaxed));
      if let Ok(t) = total_read_time.lock() {
        b.add_file_read_time(*t);
      }
    }

    issues
  }
}

struct WorkItem {
  name: String,
  version: String,
  pkg_path: PathBuf,
  package_json: serde_json::Value,
  dependency_type: DependencyType,
  is_transient: bool,
  is_root: bool,
  is_local: bool,
}

fn is_test_file(filename: &str) -> bool {
  let lower = filename.to_lowercase();

  if lower.ends_with(".test.js")
    || lower.ends_with(".test.ts")
    || lower.ends_with(".test.mjs")
    || lower.ends_with(".test.cjs")
    || lower.ends_with(".spec.js")
    || lower.ends_with(".spec.ts")
    || lower.ends_with(".spec.mjs")
    || lower.ends_with(".spec.cjs")
    || lower.ends_with(".tests.js")
    || lower.ends_with(".tests.ts")
    || lower.ends_with(".specs.js")
    || lower.ends_with(".specs.ts")
    || lower.ends_with("_test.js")
    || lower.ends_with("_test.ts")
    || lower.ends_with("_spec.js")
    || lower.ends_with("_spec.ts")
    || lower.ends_with("-test.js")
    || lower.ends_with("-test.ts")
    || lower.ends_with("-spec.js")
    || lower.ends_with("-spec.ts")
  {
    return true;
  }

  let stem = lower
    .strip_suffix(".js")
    .or_else(|| lower.strip_suffix(".ts"))
    .or_else(|| lower.strip_suffix(".mjs"))
    .or_else(|| lower.strip_suffix(".cjs"))
    .unwrap_or(&lower);

  matches!(
    stem,
    "test"
      | "tests"
      | "spec"
      | "specs"
      | "test-helper"
      | "test-helpers"
      | "test-utils"
      | "test-setup"
      | "setup-tests"
      | "jest.config"
      | "jest.setup"
      | "vitest.config"
      | "vitest.setup"
      | "mocha.opts"
      | "karma.conf"
  )
}

fn apply_severity_override(
  mut issues: Vec<Issue>,
  analyzer_name: &str,
  config: &Config,
) -> Vec<Issue> {
  if let Some(severity_str) = config.get_analyzer_severity(analyzer_name) {
    if let Ok(severity) = severity_str.parse::<Severity>() {
      for issue in &mut issues {
        issue.severity = severity;
      }
    }
  }
  issues
}

#[cfg(test)]
mod analyzer_tests {
  use super::*;

  #[test]
  fn test_analyzer_creation() {
    let config = Config::default();
    let analyzer = Analyzer::new(&config, false, None);

    assert_eq!(analyzer.file_analyzer_count(), 14);
    assert_eq!(analyzer.package_analyzer_count(), 8);
  }

  #[test]
  fn test_analyzer_offline_mode() {
    let config = Config::default();
    let analyzer = Analyzer::new(&config, true, None);

    assert!(analyzer.is_offline());
    assert_eq!(analyzer.package_analyzer_count(), 3);
  }

  #[test]
  fn test_disabled_analyzer() {
    let mut config = Config::default();
    let mut analyzer_config = crate::config::AnalyzerConfig::default();
    analyzer_config.enabled = Some(false);
    config.analyzers.insert("buffer".to_string(), analyzer_config);

    let analyzer = Analyzer::new(&config, false, None);
    assert_eq!(analyzer.file_analyzer_count(), 13);
  }

  #[test]
  fn test_analyzer_filter() {
    let config = Config::default();
    let filter = vec!["deprecated".to_string(), "cve".to_string()];
    let analyzer = Analyzer::new(&config, false, Some(&filter));

    assert_eq!(analyzer.file_analyzer_count(), 0);
    assert_eq!(analyzer.package_analyzer_count(), 2);
  }

  #[test]
  fn test_analyzer_filter_case_insensitive() {
    let config = Config::default();
    let filter = vec!["BUFFER".to_string(), "Env".to_string()];
    let analyzer = Analyzer::new(&config, false, Some(&filter));

    assert_eq!(analyzer.file_analyzer_count(), 2);
    assert_eq!(analyzer.package_analyzer_count(), 0);
  }

  #[test]
  fn test_is_test_file_dot_test() {
    assert!(is_test_file("foo.test.js"));
    assert!(is_test_file("foo.test.ts"));
    assert!(is_test_file("foo.test.mjs"));
    assert!(is_test_file("foo.test.cjs"));
    assert!(is_test_file("Component.Test.JS"));
  }

  #[test]
  fn test_is_test_file_dot_spec() {
    assert!(is_test_file("foo.spec.js"));
    assert!(is_test_file("foo.spec.ts"));
    assert!(is_test_file("foo.spec.mjs"));
    assert!(is_test_file("foo.spec.cjs"));
  }

  #[test]
  fn test_is_test_file_underscore_and_dash() {
    assert!(is_test_file("foo_test.js"));
    assert!(is_test_file("foo_spec.ts"));
    assert!(is_test_file("foo-test.js"));
    assert!(is_test_file("foo-spec.ts"));
  }

  #[test]
  fn test_is_test_file_plural() {
    assert!(is_test_file("foo.tests.js"));
    assert!(is_test_file("foo.specs.ts"));
  }

  #[test]
  fn test_is_test_file_config_files() {
    assert!(is_test_file("jest.config.js"));
    assert!(is_test_file("jest.setup.ts"));
    assert!(is_test_file("vitest.config.js"));
    assert!(is_test_file("vitest.setup.ts"));
    assert!(is_test_file("karma.conf.js"));
  }

  #[test]
  fn test_is_test_file_helper_files() {
    assert!(is_test_file("test.js"));
    assert!(is_test_file("tests.js"));
    assert!(is_test_file("spec.js"));
    assert!(is_test_file("test-helper.js"));
    assert!(is_test_file("test-helpers.ts"));
    assert!(is_test_file("test-utils.js"));
    assert!(is_test_file("test-setup.js"));
    assert!(is_test_file("setup-tests.js"));
  }

  #[test]
  fn test_is_test_file_non_test() {
    assert!(!is_test_file("index.js"));
    assert!(!is_test_file("main.ts"));
    assert!(!is_test_file("utils.mjs"));
    assert!(!is_test_file("helper.cjs"));
    assert!(!is_test_file("contest.js"));
    assert!(!is_test_file("fastest.js"));
    assert!(!is_test_file("inspect.js"));
  }

  #[test]
  fn test_trust_score_no_issues() {
    let score = TrustScore::calculate(&[]);
    assert_eq!(score.score, 100.0);
    assert_eq!(score.trust_level(), "High");
  }

  #[test]
  fn test_trust_score_low_issues() {
    let issues = vec![
      Issue {
        issue_type: "test".to_string(),
        line: 1,
        message: "test".to_string(),
        severity: Severity::Low,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      },
      Issue {
        issue_type: "test".to_string(),
        line: 2,
        message: "test".to_string(),
        severity: Severity::Low,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      },
    ];
    let score = TrustScore::calculate(&issues);
    assert!(score.score > 95.0 && score.score < 100.0);
    assert_eq!(score.low_count, 2);
    assert_eq!(score.trust_level(), "High");
  }

  #[test]
  fn test_trust_score_critical_issues() {
    let issues = vec![Issue {
      issue_type: "test".to_string(),
      line: 1,
      message: "test".to_string(),
      severity: Severity::Critical,
      code: None,
      analyzer: None,
      id: None,
      file: None,
    }];
    let score = TrustScore::calculate(&issues);
    assert!(score.score > 60.0 && score.score < 75.0);
    assert_eq!(score.critical_count, 1);
    assert_eq!(score.trust_level(), "Low");
  }

  #[test]
  fn test_trust_score_mixed_issues() {
    let issues = vec![
      Issue {
        issue_type: "test".to_string(),
        line: 1,
        message: "test".to_string(),
        severity: Severity::Critical,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      },
      Issue {
        issue_type: "test".to_string(),
        line: 2,
        message: "test".to_string(),
        severity: Severity::High,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      },
      Issue {
        issue_type: "test".to_string(),
        line: 3,
        message: "test".to_string(),
        severity: Severity::Medium,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      },
    ];
    let score = TrustScore::calculate(&issues);
    assert_eq!(score.critical_count, 1);
    assert_eq!(score.high_count, 1);
    assert_eq!(score.medium_count, 1);
    assert!(score.score > 30.0 && score.score < 60.0);
    assert_eq!(score.trust_level(), "Very Low");
  }

  #[test]
  fn test_trust_score_minimum_zero() {
    let issues: Vec<Issue> = (0..50)
      .map(|i| Issue {
        issue_type: "test".to_string(),
        line: i,
        message: "test".to_string(),
        severity: Severity::Critical,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      })
      .collect();
    let score = TrustScore::calculate(&issues);
    assert_eq!(score.score, 0.0); // Should be capped at 0
    assert_eq!(score.trust_level(), "Very Low");
  }

  #[test]
  fn test_trust_score_many_low_issues_stays_reasonable() {
    let issues: Vec<Issue> = (0..145)
      .map(|i| Issue {
        issue_type: "test".to_string(),
        line: i,
        message: "test".to_string(),
        severity: Severity::Low,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      })
      .collect();
    let score = TrustScore::calculate(&issues);
    // With logarithmic scaling, 145 low issues should give penalty of ln(146)*1*3 ≈ 15
    // So score should be around 85, not 0
    assert!(score.score > 80.0, "Score {} should be > 80 for 145 low issues", score.score);
    // Moderate (70-89) is acceptable for many low issues
    assert!(
      score.trust_level() == "High" || score.trust_level() == "Moderate",
      "Trust level should be High or Moderate, got {}",
      score.trust_level()
    );
  }

  #[test]
  fn test_dependency_type_display() {
    assert_eq!(DependencyType::Direct.as_str(), "direct");
    assert_eq!(DependencyType::Dev.as_str(), "dev");
    assert_eq!(DependencyType::Optional.as_str(), "optional");
    assert_eq!(DependencyType::Unknown.as_str(), "unknown");
  }
}
