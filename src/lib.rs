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
pub mod cache;
pub mod config;
pub mod error;
pub mod prefetch;
pub mod registry;
pub mod report;
pub mod util;

use crate::analyzers::{AnalyzeContext, Analyzer};
use crate::cache::PackageCache;
use crate::config::Config;
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

  let config = Config::load(cli.config.as_deref(), Some(&working_dir))?;

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

  let spinner = if !cli.verbose.is_present() {
    Some(Spinner::new(spinners::Dots, "Analyzing packages...", Color::Cyan))
  } else {
    info!("Starting analysis of {}", node_modules_path.display());
    None
  };

  let start_time = std::time::Instant::now();
  let analyze_ctx = AnalyzeContext::new(
    &node_modules_path,
    &config,
    cache.as_ref(),
    &ignore_issues,
    cli.fail_fast,
    cli.concurrency,
    cli.offline,
  );
  let results = analyzer.analyze_packages(&analyze_ctx).await?;

  let duration = start_time.elapsed();
  if let Some(mut s) = spinner {
    s.stop();
  }

  let report_ctx = ReportContext::new(&config.report_level, cli.only_new)
    .with_json_output(cli.json.as_deref())
    .with_yaml_output(cli.yaml.as_deref());

  reporter.report(&results, &report_ctx).map_err(|e| NapiError::from_reason(e.to_string()))?;

  println!("Analysis completed in {:.2?}", duration);
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
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn verify_cli() {
    Cli::command().debug_assert()
  }
}
