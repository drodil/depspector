#[macro_use]
extern crate napi_derive;

use clap::{CommandFactory, FromArgMatches, Parser};
use clap_verbosity_flag::Verbosity;
use log::{debug, info};
use napi::bindgen_prelude::{Error as NapiError, Result};
use spinoff::{spinners, Color, Spinner};
use std::path::PathBuf;

pub mod analyzers;
pub mod ast;
pub mod benchmark;
pub mod cache;
pub mod config;
pub mod dependencies;
pub mod error;
pub mod prefetch;
pub mod registry;
pub mod report;
pub mod util;

use crate::analyzers::{AnalyzeContext, Analyzer};
use crate::benchmark::{print_benchmark_report, BenchmarkCollector};
use crate::cache::PackageCache;
use crate::config::Config;
use crate::dependencies::DependencyGraph;
use crate::error::format_cli_error;
use crate::report::{ReportContext, Reporter};

#[allow(dead_code)]
#[napi]
pub async fn run(args: Vec<String>) -> Result<()> {
  std::panic::set_hook(Box::new(|info| {
    eprintln!("PANIC: {}", info);
  }));
  let matches = Cli::command().get_matches_from(args);
  let cli = Cli::from_arg_matches(&matches).map_err(format_cli_error::<Cli>)?;

  let mut logger = env_logger::Builder::new();
  if cli.verbose.is_present() {
    logger.filter_level(cli.verbose.log_level_filter());
  } else {
    logger.filter_level(log::LevelFilter::Info);
  }
  logger.init();

  let working_dir = cli
    .cwd
    .canonicalize()
    .map_err(|e| NapiError::from_reason(format!("Working directory not found: {}", e)))?;

  let package_json_path = working_dir.join("package.json");
  if !package_json_path.exists() {
    return Err(NapiError::from_reason(format!(
      "No package.json found at {}. Please run depspector from a directory containing a package.json file.",
      package_json_path.display()
    )));
  }

  let mut config = Config::load(cli.config.as_deref(), Some(&working_dir))?;

  if cli.include_tests {
    config.include_tests = true;
  }
  if cli.include_dev_deps {
    config.include_dev_deps = true;
  }
  if cli.include_optional_deps {
    config.include_optional_deps = true;
  }
  if cli.skip_peer_deps {
    config.include_peer_deps = false;
  }
  if cli.skip_transient {
    config.skip_transient = true;
  }

  let node_modules_path = working_dir.join(&cli.path);
  if !node_modules_path.exists() {
    return Err(NapiError::from_reason(format!(
      "node_modules not found at {}",
      node_modules_path.display()
    )));
  }

  debug!("Working directory: {:?}", working_dir);
  debug!("node_modules path: {:?}", node_modules_path);

  let only_analyzers = if cli.analyzer.is_empty() { None } else { Some(cli.analyzer.as_slice()) };
  let analyzer = Analyzer::new(&config, cli.offline, only_analyzers);
  let reporter = Reporter::new();
  let cache = if cli.cache {
    Some(PackageCache::new(&config.cache_dir, &working_dir, &node_modules_path)?)
  } else {
    None
  };

  let ignore_issues: Vec<String> =
    config.ignore_issues.iter().cloned().chain(cli.ignore_issue.iter().cloned()).collect();

  if let Some(ref cache) = cache {
    if cli.clear_cache {
      cache.clear_all()?;
      info!("Cache cleared");
    }
  }

  let spinner = if !cli.verbose.is_present() && !cli.benchmark {
    Some(Spinner::new(spinners::Dots, "Analyzing packages...", Color::Cyan))
  } else {
    info!("Starting analysis of {}", node_modules_path.display());
    None
  };

  let benchmark_collector = if cli.benchmark { Some(BenchmarkCollector::new()) } else { None };

  // Build dependency graph to determine package types for reporting
  let dependency_graph = DependencyGraph::build(&working_dir, &node_modules_path);
  if dependency_graph.total_count() > 0 {
    debug!("Built dependency graph with {} packages", dependency_graph.total_count());
  } else {
    debug!("No packages found in dependency graph");
  }
  if !config.include_dev_deps {
    info!("Found {} dev packages that will be skipped", dependency_graph.dev_count());
  }
  if !config.include_optional_deps {
    info!("Found {} optional packages that will be skipped", dependency_graph.optional_count());
  }
  if !config.include_peer_deps {
    info!("Found {} peer packages that will be skipped", dependency_graph.peer_count());
  }

  let start_time = std::time::Instant::now();
  let analyze_ctx = AnalyzeContext::new(
    &node_modules_path,
    &config,
    cache.as_ref(),
    &ignore_issues,
    cli.fail_fast,
    cli.concurrency,
    cli.offline,
  )
  .with_benchmark(benchmark_collector.clone())
  .with_dependency_graph(Some(dependency_graph));
  let results = analyzer.analyze_packages(&analyze_ctx).await?;

  let duration = start_time.elapsed();
  if let Some(mut s) = spinner {
    s.stop();
  }

  let report_level = cli.report_level.as_deref().unwrap_or(config.report_level.as_str());
  let report_ctx = ReportContext::new(report_level, cli.only_new)
    .with_json_output(cli.json.as_deref())
    .with_yaml_output(cli.yaml.as_deref())
    .with_csv_output(cli.csv.as_deref());

  reporter.report(&results, &report_ctx).map_err(|e| NapiError::from_reason(e.to_string()))?;

  // After reporting, print information about ignored issue IDs that had no matches
  if !ignore_issues.is_empty() {
    if let Ok(used_ignored) = analyze_ctx.ignored_ids.lock() {
      let used: std::collections::HashSet<_> = used_ignored.iter().cloned().collect();
      let unused: Vec<_> = ignore_issues.iter().filter(|id| !used.contains(*id)).cloned().collect();
      if !unused.is_empty() {
        println!("Note: The following ignored issue IDs had no matching issues:");
        for id in unused {
          println!("  - {}", id);
        }
      }
    }
  }

  if let Some(collector) = benchmark_collector {
    print_benchmark_report(&collector.get_results(), duration);
  } else {
    println!("Analysis completed in {:.2?}", duration);
  }

  let exit_level = config.exit_with_failure_on_level.as_deref().unwrap_or("high");
  if exit_level != "off" && reporter.has_issues_at_level(&results, exit_level) {
    return Err(NapiError::from_reason("Analysis found issues at failure level"));
  }

  Ok(())
}

#[derive(Parser)]
#[clap(
  author = "Heikki Hellgren",
  name = "depspector",
  version = env!("CARGO_PKG_VERSION"),
  about = "Post-install security analysis tool for npm dependencies",
  long_about = "Depspector analyzes your npm dependencies for potential security issues, malware patterns, and suspicious code. It provides comprehensive detection of various attack vectors including environment variable access, network calls, file system operations, eval usage, obfuscated code, and more."
)]
#[clap(no_binary_name = true)]
struct Cli {
  #[clap(short, long, default_value = "./node_modules", help = "Path to node_modules directory")]
  path: PathBuf,
  #[clap(short, long, help = "Path to configuration file")]
  config: Option<PathBuf>,
  #[clap(long, default_value = ".", help = "Working directory for analysis")]
  cwd: PathBuf,
  #[clap(long, default_value_t = true, action = clap::ArgAction::Set, help = "Enable package result caching")]
  cache: bool,
  #[clap(long, help = "Clear cache before scanning")]
  clear_cache: bool,
  #[clap(long, help = "Stop on first issue at or above failure level")]
  fail_fast: bool,
  #[clap(long, help = "Show only new issues (exclude cached)")]
  only_new: bool,
  #[clap(long, help = "Disable network-dependent analyzers")]
  offline: bool,
  #[clap(long, num_args = 1.., help = "Issue IDs to ignore")]
  ignore_issue: Vec<String>,
  #[clap(long, short = 'a', num_args = 1.., help = "Run only specific analyzers (e.g., --analyzer cve --analyzer deprecated)")]
  analyzer: Vec<String>,
  #[clap(flatten)]
  verbose: Verbosity,
  #[clap(long, help = "Max concurrent package analyses (defaults to CPU cores)")]
  concurrency: Option<usize>,
  #[clap(long, help = "Output report as JSON to file")]
  json: Option<PathBuf>,
  #[clap(long, help = "Output report as YAML to file")]
  yaml: Option<PathBuf>,
  #[clap(long, help = "Output report as CSV to file")]
  csv: Option<PathBuf>,
  #[clap(long, help = "Minimum severity level to report (critical, high, medium, low, info)")]
  report_level: Option<String>,
  #[clap(long, help = "Show detailed benchmark/timing information for each analyzer")]
  benchmark: bool,
  #[clap(long, help = "Include test files in analysis (skipped by default)")]
  include_tests: bool,
  #[clap(long, help = "Include dev dependencies in analysis (excluded by default)")]
  include_dev_deps: bool,
  #[clap(long, help = "Include optional dependencies in analysis (excluded by default)")]
  include_optional_deps: bool,
  #[clap(long, help = "Skip peer dependencies in analysis (included by default)")]
  skip_peer_deps: bool,
  #[clap(
    long,
    help = "Skip transient dependencies (only scan direct and dev deps from root package.json)"
  )]
  skip_transient: bool,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn verify_cli() {
    Cli::command().debug_assert()
  }
}
