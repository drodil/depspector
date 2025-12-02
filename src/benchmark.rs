use colored::Colorize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Stores benchmark results for all analyzers
#[derive(Debug, Default)]
pub struct BenchmarkResults {
  /// Map of analyzer name to timing data
  pub analyzers: HashMap<String, AnalyzerStats>,
  /// Total files analyzed
  pub total_files: usize,
  /// Total packages analyzed
  pub total_packages: usize,
  /// Total bytes processed
  pub total_bytes: usize,
  /// Time spent discovering packages
  pub discovery_time: Duration,
  /// Time spent reading files
  pub file_read_time: Duration,
  /// Time spent prefetching registry data
  pub prefetch_time: Duration,
  /// Total time spent parsing AST
  pub ast_parse_time: Duration,
  /// Number of files parsed with AST
  pub ast_files_parsed: usize,
  /// Slowest files to parse (path, duration, size)
  pub slowest_ast_parses: Vec<(String, Duration, usize)>,
}

#[derive(Debug, Default, Clone)]
pub struct AnalyzerStats {
  /// Total time spent in this analyzer
  pub total_time: Duration,
  /// Number of files/packages analyzed
  pub invocations: usize,
  /// Number of issues found
  pub issues_found: usize,
  /// Min time for a single invocation
  pub min_time: Option<Duration>,
  /// Max time for a single invocation
  pub max_time: Option<Duration>,
}

impl AnalyzerStats {
  pub fn record(&mut self, duration: Duration, issues: usize) {
    self.total_time += duration;
    self.invocations += 1;
    self.issues_found += issues;

    match self.min_time {
      Some(min) if duration < min => self.min_time = Some(duration),
      None => self.min_time = Some(duration),
      _ => {}
    }

    match self.max_time {
      Some(max) if duration > max => self.max_time = Some(duration),
      None => self.max_time = Some(duration),
      _ => {}
    }
  }

  pub fn avg_time(&self) -> Duration {
    if self.invocations == 0 {
      Duration::ZERO
    } else {
      self.total_time / self.invocations as u32
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct BenchmarkCollector {
  inner: Arc<Mutex<BenchmarkResults>>,
}

impl BenchmarkCollector {
  pub fn new() -> Self {
    Self { inner: Arc::new(Mutex::new(BenchmarkResults::default())) }
  }

  pub fn record_analyzer(&self, name: &str, duration: Duration, issues: usize) {
    let mut results = self.inner.lock().unwrap();
    results.analyzers.entry(name.to_string()).or_default().record(duration, issues);
  }

  pub fn record_discovery_time(&self, duration: Duration) {
    let mut results = self.inner.lock().unwrap();
    results.discovery_time = duration;
  }

  pub fn record_prefetch_time(&self, duration: Duration) {
    let mut results = self.inner.lock().unwrap();
    results.prefetch_time = duration;
  }

  pub fn add_file_read_time(&self, duration: Duration) {
    let mut results = self.inner.lock().unwrap();
    results.file_read_time += duration;
  }

  pub fn add_files(&self, count: usize) {
    let mut results = self.inner.lock().unwrap();
    results.total_files += count;
  }

  pub fn add_packages(&self, count: usize) {
    let mut results = self.inner.lock().unwrap();
    results.total_packages += count;
  }

  pub fn add_bytes(&self, bytes: usize) {
    let mut results = self.inner.lock().unwrap();
    results.total_bytes += bytes;
  }

  pub fn record_ast_parse(&self, file_path: &str, duration: Duration, file_size: usize) {
    let mut results = self.inner.lock().unwrap();
    results.ast_parse_time += duration;
    results.ast_files_parsed += 1;

    results.slowest_ast_parses.push((file_path.to_string(), duration, file_size));
    results.slowest_ast_parses.sort_by(|a, b| b.1.cmp(&a.1));
    results.slowest_ast_parses.truncate(10);
  }

  pub fn get_results(&self) -> BenchmarkResults {
    let results = self.inner.lock().unwrap();
    BenchmarkResults {
      analyzers: results.analyzers.clone(),
      total_files: results.total_files,
      total_packages: results.total_packages,
      total_bytes: results.total_bytes,
      discovery_time: results.discovery_time,
      file_read_time: results.file_read_time,
      prefetch_time: results.prefetch_time,
      ast_parse_time: results.ast_parse_time,
      ast_files_parsed: results.ast_files_parsed,
      slowest_ast_parses: results.slowest_ast_parses.clone(),
    }
  }
}

pub fn print_benchmark_report(results: &BenchmarkResults, total_duration: Duration) {
  println!("\n{}", "═".repeat(70).bright_blue());
  println!("{}", " BENCHMARK RESULTS ".bright_blue().bold());
  println!("{}", "═".repeat(70).bright_blue());

  println!("\n{}", "Summary".bold().underline());
  println!("  Wall-clock time:   {:>10.2?}", total_duration);
  println!("  Packages analyzed: {:>10}", results.total_packages);
  println!("  Files analyzed:    {:>10}", results.total_files);
  println!("  Bytes processed:   {:>10}", format_bytes(results.total_bytes));

  if total_duration.as_secs_f64() > 0.0 {
    let throughput = results.total_bytes as f64 / total_duration.as_secs_f64() / 1024.0 / 1024.0;
    println!("  Throughput:        {:>10.2} MB/s", throughput);
  }

  // Calculate cumulative time (sum of all parallel work)
  let cumulative_analysis: Duration = results.analyzers.values().map(|s| s.total_time).sum();

  // Estimate parallelism factor
  let parallelism = if total_duration.as_nanos() > 0 {
    cumulative_analysis.as_secs_f64() / total_duration.as_secs_f64()
  } else {
    1.0
  };

  println!("\n{}", "Phase Timing (wall-clock)".bold().underline());
  println!(
    "  Discovery:         {:>10.2?} ({:>5.1}%)",
    results.discovery_time,
    percentage(results.discovery_time, total_duration)
  );
  println!(
    "  Prefetch:          {:>10.2?} ({:>5.1}%)",
    results.prefetch_time,
    percentage(results.prefetch_time, total_duration)
  );
  println!(
    "  File I/O:          {:>10.2?} ({:>5.1}%)",
    results.file_read_time,
    percentage(results.file_read_time, total_duration)
  );

  // AST Parsing section
  if results.ast_files_parsed > 0 {
    println!("\n{}", "AST Parsing".bold().underline());
    println!("  Files parsed:      {:>10}", results.ast_files_parsed);
    println!("  Total parse time:  {:>10.2?} (cumulative)", results.ast_parse_time);
    let avg_parse = results.ast_parse_time / results.ast_files_parsed as u32;
    println!("  Avg parse time:    {:>10.2?}", avg_parse);

    if !results.slowest_ast_parses.is_empty() {
      println!("\n  {}", "Slowest files to parse:".dimmed());
      for (path, duration, size) in results.slowest_ast_parses.iter().take(5) {
        let line = format!("    {:>10.2?}  {:>10}  {}", duration, format_bytes(*size), path);
        if *duration > Duration::from_millis(100) {
          println!("{}", line.red());
        } else if *duration > Duration::from_millis(10) {
          println!("{}", line.yellow());
        } else {
          println!("{}", line);
        }
      }
    }
  }

  println!(
    "\n{} {}",
    "Analyzer Performance".bold().underline(),
    "(cumulative time across parallel executions)".dimmed()
  );
  println!(
    "  {:<20} {:>10} {:>10} {:>10} {:>10} {:>8}",
    "Analyzer", "Cumul.", "Avg", "Min", "Max", "Issues"
  );
  println!("  {}", "─".repeat(68));

  let mut analyzers: Vec<_> = results.analyzers.iter().collect();
  analyzers.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));

  for (name, stats) in analyzers {
    // Color based on average time per invocation, not total
    let avg = stats.avg_time();
    let color = if avg > Duration::from_secs(1) {
      "red"
    } else if avg > Duration::from_millis(100) {
      "yellow"
    } else {
      "green"
    };

    let line = format!(
      "  {:<20} {:>10.2?} {:>10.2?} {:>10.2?} {:>10.2?} {:>8}",
      name,
      stats.total_time,
      avg,
      stats.min_time.unwrap_or(Duration::ZERO),
      stats.max_time.unwrap_or(Duration::ZERO),
      stats.issues_found
    );

    match color {
      "red" => println!("{}", line.red()),
      "yellow" => println!("{}", line.yellow()),
      _ => println!("{}", line.green()),
    }
  }

  println!(
    "\n  {} Cumulative: {:.2?} | Parallelism: {:.1}x",
    "∑".dimmed(),
    cumulative_analysis,
    parallelism
  );

  println!("\n{}", "Slowest Analyzers (by avg time)".bold().underline());

  let mut by_avg: Vec<_> = results
    .analyzers
    .iter()
    .filter(|(_, s)| s.invocations > 0 && s.avg_time() > Duration::from_millis(1))
    .collect();
  by_avg.sort_by(|a, b| b.1.avg_time().cmp(&a.1.avg_time()));

  if by_avg.is_empty() {
    println!("  {} All analyzers are fast (<1ms avg)", "✓".green());
  } else {
    for (name, stats) in by_avg.iter().take(5) {
      let avg = stats.avg_time();
      let max = stats.max_time.unwrap_or(Duration::ZERO);
      println!(
        "  {} {:<20} avg: {:>10.2?}  max: {:>10.2?}  ({} calls)",
        "→".yellow(),
        name.bold(),
        avg,
        max,
        stats.invocations
      );
    }
  }

  println!("\n{}", "═".repeat(70).bright_blue());
}

fn percentage(part: Duration, total: Duration) -> f64 {
  if total.as_nanos() == 0 {
    0.0
  } else {
    (part.as_nanos() as f64 / total.as_nanos() as f64) * 100.0
  }
}

fn format_bytes(bytes: usize) -> String {
  if bytes >= 1024 * 1024 * 1024 {
    format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
  } else if bytes >= 1024 * 1024 {
    format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
  } else if bytes >= 1024 {
    format!("{:.2} KB", bytes as f64 / 1024.0)
  } else {
    format!("{} B", bytes)
  }
}
