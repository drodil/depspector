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

pub mod buffer;
pub mod dynamic;
pub mod env;
pub mod eval;
pub mod fs;
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

pub use buffer::BufferAnalyzer;
pub use cooldown::CooldownAnalyzer;
pub use cve::CVEAnalyzer;
pub use deprecated::DeprecatedAnalyzer;
pub use dormant::DormantAnalyzer;
pub use dynamic::DynamicAnalyzer;
pub use env::EnvAnalyzer;
pub use eval::EvalAnalyzer;
pub use fs::FsAnalyzer;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
  pub file: String,

  #[serde(default)]
  pub package: Option<String>,

  pub issues: Vec<Issue>,

  #[serde(default)]
  pub is_from_cache: bool,
}

impl AnalysisResult {
  pub fn new(file: &str) -> Self {
    Self { file: file.to_string(), package: None, issues: vec![], is_from_cache: false }
  }

  pub fn with_package(file: &str, package: &str) -> Self {
    Self {
      file: file.to_string(),
      package: Some(package.to_string()),
      issues: vec![],
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
}

impl<'a> AnalyzeContext<'a> {
  pub fn new(
    node_modules_path: &'a Path,
    config: &'a Config,
    cache: Option<&'a PackageCache>,
    ignore_issues: &'a [String],
    fail_fast: bool,
    concurrency: Option<usize>,
    offline: bool,
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
    let file_size = source.len();
    let max_file_size = config.max_file_size;

    // Check if any AST analyzer will run on this file
    let needs_ast = file_size <= max_file_size && self.file_analyzers.iter().any(|a| a.uses_ast());

    // Parse AST once if needed, share across all analyzers
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
      package_name: None,
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
    self.analyze_package_with_benchmark(pkg_ctx, None).await
  }

  pub async fn analyze_package_with_benchmark(
    &self,
    pkg_ctx: &PackageContext<'_>,
    benchmark: Option<&BenchmarkCollector>,
  ) -> Vec<Issue> {
    use futures::future::join_all;

    let futures: Vec<_> = self
      .package_analyzers
      .iter()
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

    let discovery_start = std::time::Instant::now();
    let (cached_results, work_items) = self.discover_packages(ctx);
    if let Some(ref b) = ctx.benchmark {
      b.record_discovery_time(discovery_start.elapsed());
      b.add_packages(work_items.len() + cached_results.len());
    }

    let mut results = cached_results;

    let prefetch_start = std::time::Instant::now();
    let prefetched = self.prefetch_data(&work_items, ctx).await;
    if let Some(ref b) = ctx.benchmark {
      b.record_prefetch_time(prefetch_start.elapsed());
    }

    let mut analyzed: Vec<AnalysisResult> = stream::iter(work_items)
      .map(|wi| self.analyze_single_package(wi, ctx, prefetched.clone()))
      .buffer_unordered(ctx.concurrency)
      .collect()
      .await;

    results.append(&mut analyzed);

    if ctx.fail_fast && results.iter().any(|r| !r.issues.is_empty()) {
      return Ok(results.into_iter().take(1).collect());
    }
    Ok(results)
  }

  fn discover_packages(&self, ctx: &AnalyzeContext<'_>) -> (Vec<AnalysisResult>, Vec<WorkItem>) {
    use std::fs;
    use std::sync::Mutex;
    use walkdir::WalkDir;

    let cached_results = Mutex::new(Vec::<AnalysisResult>::new());
    let work_items = Mutex::new(Vec::<WorkItem>::new());

    WalkDir::new(ctx.node_modules_path)
      .follow_links(false)
      .into_iter()
      .par_bridge()
      .filter_map(|entry| entry.ok())
      .filter(|entry| {
        if entry.file_type().is_symlink() {
          return false;
        }
        if entry.file_type().is_dir() {
          let dir_name = entry.file_name().to_string_lossy();
          if is_excluded_dir(&dir_name, ctx.config) {
            return false;
          }
        }
        entry.file_name() == "package.json"
      })
      .for_each(|entry| {
        let pkg_path = match entry.path().parent() {
          Some(p) => p.to_path_buf(),
          None => return,
        };
        if pkg_path.components().any(|c| {
          let s = c.as_os_str().to_string_lossy();
          s == "dist" || s == "build"
        }) {
          return;
        }

        let package_json_content = match fs::read_to_string(entry.path()) {
          Ok(c) => c,
          Err(_) => return,
        };
        let package_json: serde_json::Value = match serde_json::from_str(&package_json_content) {
          Ok(v) => v,
          Err(_) => return,
        };
        let name = package_json.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
        let version = package_json.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0");
        if ctx.config.exclude.iter().any(|e| name.contains(e)) {
          return;
        }

        if let Some(cache) = ctx.cache {
          if let Some(cached) = cache.get(name, version) {
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
          name: name.to_string(),
          version: version.to_string(),
          pkg_path,
          package_json,
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
    let pkg_ctx = PackageContext {
      name: &wi.name,
      version: &wi.version,
      path: &wi.pkg_path,
      package_json: &wi.package_json,
      config: ctx.config,
      prefetched,
    };

    let benchmark = ctx.benchmark.as_ref();
    let (package_issues, js_entries) = tokio::join!(
      self.analyze_package_with_benchmark(&pkg_ctx, benchmark),
      Self::discover_js_files(&pkg_path_clone, ctx.config)
    );

    if let Some(ref b) = ctx.benchmark {
      b.add_files(js_entries.len());
    }

    let file_issues = self.analyze_files_with_benchmark(&js_entries, ctx);

    let mut all_issues = package_issues;
    all_issues.extend(file_issues);
    all_issues.retain(|i| i.id.as_ref().map(|id| !ctx.ignore_issues.contains(id)).unwrap_or(true));

    let result = AnalysisResult {
      file: normalize_path(&wi.pkg_path.to_string_lossy()),
      package: Some(wi.name.clone()),
      issues: all_issues,
      is_from_cache: false,
    };

    if let Some(cache) = ctx.cache {
      let _ = cache.set(&wi.name, &wi.version, &result);
    }

    result
  }

  async fn discover_js_files(pkg_path: &Path, config: &Config) -> Vec<PathBuf> {
    use walkdir::WalkDir;

    WalkDir::new(pkg_path)
      .follow_links(false)
      .into_iter()
      .filter_map(|e| e.ok())
      .filter(|e| {
        if e.file_type().is_symlink() {
          return false;
        }
        let rel_segments: Vec<String> = e
          .path()
          .strip_prefix(pkg_path)
          .unwrap_or(e.path())
          .components()
          .map(|c| c.as_os_str().to_string_lossy().to_string())
          .collect();
        if rel_segments.iter().any(|s| is_excluded_dir(s, config)) {
          return false;
        }
        if rel_segments.iter().any(|s| s == "node_modules") {
          return false;
        }
        let fname = e.file_name().to_string_lossy();
        if fname.ends_with(".d.ts") || fname.ends_with(".min.js") {
          return false;
        }
        if fname.ends_with(".test.js") || fname.ends_with(".test.ts") {
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

        let mut file_issues =
          self.analyze_file_with_benchmark(&source, js_path, ctx.config, ctx.benchmark.as_ref());
        file_issues
          .retain(|i| i.id.as_ref().map(|id| !ctx.ignore_issues.contains(id)).unwrap_or(true));
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
}

fn is_excluded_dir(segment: &str, config: &Config) -> bool {
  matches!(
    segment,
    ".bin" | "test" | "tests" | "__tests__" | "example" | "examples" | "dist" | "build"
  ) || config.exclude.iter().any(|e| e == segment)
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

    assert_eq!(analyzer.file_analyzer_count(), 12);
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
    assert_eq!(analyzer.file_analyzer_count(), 11);
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
}
