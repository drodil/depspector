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
    }
  }
}

pub fn print_benchmark_report(results: &BenchmarkResults, total_duration: Duration) {
  println!("\n{}", "═".repeat(70).bright_blue());
  println!("{}", " BENCHMARK RESULTS ".bright_blue().bold());
  println!("{}", "═".repeat(70).bright_blue());

  println!("\n{}", "Summary".bold().underline());
  println!("  Total time:        {:>10.2?}", total_duration);
  println!("  Packages analyzed: {:>10}", results.total_packages);
  println!("  Files analyzed:    {:>10}", results.total_files);
  println!("  Bytes processed:   {:>10}", format_bytes(results.total_bytes));

  if total_duration.as_secs_f64() > 0.0 {
    let throughput = results.total_bytes as f64 / total_duration.as_secs_f64() / 1024.0 / 1024.0;
    println!("  Throughput:        {:>10.2} MB/s", throughput);
  }

  println!("\n{}", "Phase Timing".bold().underline());
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

  let analysis_time: Duration = results.analyzers.values().map(|s| s.total_time).sum();
  println!(
    "  Analysis:          {:>10.2?} ({:>5.1}%)",
    analysis_time,
    percentage(analysis_time, total_duration)
  );

  println!("\n{}", "Analyzer Performance".bold().underline());
  println!(
    "  {:<20} {:>10} {:>10} {:>10} {:>10} {:>8}",
    "Analyzer", "Total", "Avg", "Min", "Max", "Issues"
  );
  println!("  {}", "─".repeat(68));

  let mut analyzers: Vec<_> = results.analyzers.iter().collect();
  analyzers.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));

  for (name, stats) in analyzers {
    let color = if stats.total_time > Duration::from_secs(1) {
      "red"
    } else if stats.total_time > Duration::from_millis(500) {
      "yellow"
    } else {
      "green"
    };

    let line = format!(
      "  {:<20} {:>10.2?} {:>10.2?} {:>10.2?} {:>10.2?} {:>8}",
      name,
      stats.total_time,
      stats.avg_time(),
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

  println!("\n{}", "Hotspots".bold().underline());

  let mut hotspots: Vec<_> =
    results.analyzers.iter().filter(|(_, s)| s.total_time > Duration::from_millis(100)).collect();
  hotspots.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));

  if hotspots.is_empty() {
    println!("  {} No significant hotspots detected", "✓".green());
  } else {
    for (name, stats) in hotspots.iter().take(3) {
      let pct = percentage(stats.total_time, total_duration);
      println!(
        "  {} {} takes {:.1}% of total time ({:.2?})",
        "→".yellow(),
        name.bold(),
        pct,
        stats.total_time
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
