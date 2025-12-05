use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use colored::*;

use crate::analyzers::{AnalysisResult, DependencyType, Severity, TrustScore};

const MAX_LINE_LENGTH: usize = 120;

fn make_path_relative(path: &str, cwd: &Path) -> String {
  if let Ok(abs_path) = std::path::PathBuf::from(path).canonicalize() {
    if let Ok(rel_path) = abs_path.strip_prefix(cwd) {
      return rel_path.to_string_lossy().to_string();
    }
  }
  path.to_string()
}

fn trust_level_colored(score: f64) -> ColoredString {
  match score as u32 {
    90..=100 => "High".green(),
    70..=89 => "Moderate".yellow(),
    50..=69 => "Low".truecolor(255, 165, 0), // Orange
    _ => "Very Low".red(),
  }
}

fn dependency_type_display(dep_type: DependencyType) -> ColoredString {
  match dep_type {
    DependencyType::Direct => "direct".green(),
    DependencyType::Dev => "dev".blue(),
    DependencyType::Optional => "optional".cyan(),
    DependencyType::Peer => "peer".magenta(),
    DependencyType::Local => "local".bright_green(),
    DependencyType::Unknown => "unknown".dimmed(),
  }
}

fn truncate_line(s: &str, max_len: usize) -> String {
  let trimmed = s.trim();
  if trimmed.chars().count() > max_len {
    let truncated: String = trimmed.chars().take(max_len - 3).collect();
    format!("{}...", truncated)
  } else {
    trimmed.to_string()
  }
}

pub struct ReportContext<'a> {
  pub report_level: &'a str,
  pub only_new: bool,
  pub json_output: Option<&'a Path>,
  pub yaml_output: Option<&'a Path>,
  pub csv_output: Option<&'a Path>,
  pub working_dir: &'a Path,
}

impl<'a> ReportContext<'a> {
  pub fn new(report_level: &'a str, only_new: bool, working_dir: &'a Path) -> Self {
    Self {
      report_level,
      only_new,
      json_output: None,
      yaml_output: None,
      csv_output: None,
      working_dir,
    }
  }

  pub fn with_json_output(mut self, path: Option<&'a Path>) -> Self {
    self.json_output = path;
    self
  }

  pub fn with_yaml_output(mut self, path: Option<&'a Path>) -> Self {
    self.yaml_output = path;
    self
  }

  pub fn with_csv_output(mut self, path: Option<&'a Path>) -> Self {
    self.csv_output = path;
    self
  }
}

pub struct Reporter;

impl Reporter {
  pub fn new() -> Self {
    Self
  }

  pub fn report(&self, results: &[AnalysisResult], ctx: &ReportContext) -> std::io::Result<()> {
    let min_severity = Severity::from_str(ctx.report_level).unwrap_or(Severity::Low);

    let filtered: Vec<_> = results
      .iter()
      .filter(|r| !ctx.only_new || !r.is_from_cache)
      .filter(|r| r.issues.iter().any(|i| i.severity >= min_severity))
      .cloned()
      .collect();

    if let Some(json_path) = ctx.json_output {
      self.write_json(&filtered, json_path)?;
    }

    if let Some(yaml_path) = ctx.yaml_output {
      self.write_yaml(&filtered, yaml_path)?;
    }

    if let Some(csv_path) = ctx.csv_output {
      self.write_csv(&filtered, csv_path)?;
    }

    self.print_console(&filtered, min_severity, ctx);

    Ok(())
  }

  fn write_json(&self, results: &[AnalysisResult], path: &Path) -> std::io::Result<()> {
    let json =
      serde_json::to_string_pretty(results).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    println!("{} {}", "JSON report written to:".green(), path.display());
    Ok(())
  }

  fn write_yaml(&self, results: &[AnalysisResult], path: &Path) -> std::io::Result<()> {
    let yaml = serde_yaml::to_string(results).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut file = File::create(path)?;
    file.write_all(yaml.as_bytes())?;
    println!("{} {}", "YAML report written to:".green(), path.display());
    Ok(())
  }

  fn write_csv(&self, results: &[AnalysisResult], path: &Path) -> std::io::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr
      .write_record(["package", "file", "line", "severity", "type", "message", "code", "id"])
      .map_err(|e| std::io::Error::other(e.to_string()))?;

    for result in results {
      let package = result.package.as_deref().unwrap_or("unknown");

      for issue in &result.issues {
        let file_path = if issue.file.is_empty() {
          result.package_path.clone()
        } else if issue.file == "package.json"
          || (!issue.file.contains(std::path::MAIN_SEPARATOR) && !issue.file.contains('/'))
        {
          let pkg_path = std::path::Path::new(&result.package_path);
          pkg_path.join(&issue.file).to_string_lossy().to_string()
        } else {
          issue.file.clone()
        };
        let severity = match issue.severity {
          Severity::Critical => "critical",
          Severity::High => "high",
          Severity::Medium => "medium",
          Severity::Low => "low",
        };

        wtr
          .write_record([
            package,
            &file_path,
            &issue.line.to_string(),
            severity,
            &issue.analyzer,
            &issue.message,
            issue.code.as_deref().unwrap_or(""),
            &issue.get_id(),
          ])
          .map_err(|e| std::io::Error::other(e.to_string()))?;
      }
    }

    wtr.flush()?;
    println!("{} {}", "CSV report written to:".green(), path.display());
    Ok(())
  }

  fn print_console(
    &self,
    filtered: &[AnalysisResult],
    min_severity: Severity,
    ctx: &ReportContext,
  ) {
    if filtered.is_empty() {
      println!("{}", "✓ No issues found".green().bold());
      return;
    }

    println!("\n{}", "Security Analysis Report".bold().underline());
    println!();

    let by_package_version = self.group_by_package_version(filtered);
    let trust_scores = self.build_trust_scores(filtered);
    let sorted_packages: Vec<_> = by_package_version.iter().collect();

    self.print_packages(&sorted_packages, min_severity, ctx);
    self.print_summary(filtered);
    self.print_untrusted_packages(&trust_scores);
    self.print_deduplication_candidates(filtered);
  }

  fn group_by_package_version<'a>(
    &self,
    filtered: &'a [AnalysisResult],
  ) -> std::collections::HashMap<String, Vec<&'a AnalysisResult>> {
    let mut by_package_version: std::collections::HashMap<String, Vec<&'a AnalysisResult>> =
      std::collections::HashMap::new();

    for result in filtered {
      let pkg = result.package.clone().unwrap_or_else(|| "unknown".to_string());
      let version = result.version.as_deref().unwrap_or("unknown");
      let key = format!("{}@{}", pkg, version);
      by_package_version.entry(key).or_default().push(result);
    }

    by_package_version
  }

  fn build_trust_scores(
    &self,
    filtered: &[AnalysisResult],
  ) -> Vec<(String, TrustScore, DependencyType)> {
    let mut trust_scores: Vec<(String, TrustScore, DependencyType)> = filtered
      .iter()
      .map(|r| {
        let display_name = if let Some(v) = &r.version {
          format!("{}@{}", r.package.as_deref().unwrap_or("unknown"), v)
        } else {
          r.package.as_deref().unwrap_or("unknown").to_string()
        };
        (display_name, r.trust_score.clone(), r.dependency_type)
      })
      .collect();

    trust_scores.sort_by(|a, b| a.1.score.partial_cmp(&b.1.score).unwrap());
    trust_scores.dedup_by(|a, b| a.0 == b.0);

    trust_scores
  }

  fn print_packages(
    &self,
    sorted_packages: &[(&String, &Vec<&AnalysisResult>)],
    min_severity: Severity,
    ctx: &ReportContext,
  ) {
    let mut sorted = sorted_packages.to_vec();
    sorted.sort_by(|(key_a, _), (key_b, _)| key_a.to_lowercase().cmp(&key_b.to_lowercase()));

    for (package_version, results) in sorted {
      self.print_package_details(package_version, results, min_severity, ctx);
    }
  }

  fn print_package_details(
    &self,
    package_version: &str,
    results: &[&AnalysisResult],
    min_severity: Severity,
    ctx: &ReportContext,
  ) {
    let trust = results.first().map(|r| &r.trust_score);
    let dep_type = results.first().map(|r| r.dependency_type).unwrap_or(DependencyType::Unknown);
    let is_transient = results.first().map(|r| r.is_transient).unwrap_or(false);

    let trust_display = if let Some(t) = trust {
      format!(" [Trust: {:.0} - {}]", t.score, t.trust_level())
    } else {
      String::new()
    };

    let dep_display = if is_transient {
      format!("{} transient", dependency_type_display(dep_type))
    } else {
      format!("{}", dependency_type_display(dep_type))
    };

    println!("📦 {} ({}){}", package_version.cyan().bold(), dep_display, trust_display.dimmed());

    self.print_package_issues(results, min_severity, ctx);
    println!();
  }

  fn print_package_issues(
    &self,
    results: &[&AnalysisResult],
    min_severity: Severity,
    ctx: &ReportContext,
  ) {
    #[allow(clippy::type_complexity)]
    {
      use std::collections::BTreeMap;
      let mut grouped_issues: BTreeMap<
        (String, String, String),
        Vec<(String, usize, bool, Option<&str>)>,
      > = BTreeMap::new();

      for result in results {
        for issue in &result.issues {
          if issue.severity < min_severity {
            continue;
          }

          let file_path = if issue.file.is_empty() {
            result.package_path.clone()
          } else if issue.file == "package.json"
            || (!issue.file.contains(std::path::MAIN_SEPARATOR) && !issue.file.contains('/'))
          {
            let pkg_path = std::path::Path::new(&result.package_path);
            pkg_path.join(&issue.file).to_string_lossy().to_string()
          } else {
            issue.file.clone()
          };
          let display_path = make_path_relative(&file_path, ctx.working_dir);

          let key = (issue.message.clone(), issue.analyzer.clone(), issue.get_id());
          grouped_issues.entry(key).or_default().push((
            display_path,
            issue.line,
            result.is_from_cache,
            issue.code.as_deref(),
          ));
        }
      }

      for ((message, issue_type, id), paths_and_cache) in grouped_issues {
        let first_result = results.iter().find_map(|r| {
          r.issues
            .iter()
            .find(|i| i.message == message && i.analyzer == issue_type && i.get_id() == id)
        });

        if let Some(issue) = first_result {
          let severity_str = match issue.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".white(),
          };

          let id_display = format!(" (ID: {})", id.dimmed());

          println!("  {} [{}]{}: {}", severity_str, issue_type.dimmed(), id_display, message);

          for (path, line, is_from_cache, _) in &paths_and_cache {
            let location = if *line == 0 { path.to_string() } else { format!("{}:{}", path, line) };
            let path_display = if *is_from_cache {
              format!("    {} {}", "↺".dimmed(), location.dimmed())
            } else {
              format!("    {}", location)
            };
            println!("{}", path_display);
          }

          if let Some(code) = &issue.code {
            println!("      {}", truncate_line(code, MAX_LINE_LENGTH - 6).dimmed());
          }

          println!();
        }
      }
    }
  }

  fn print_summary(&self, filtered: &[AnalysisResult]) {
    let total_issues: usize = filtered.iter().map(|r| r.issues.len()).sum();
    let critical =
      filtered.iter().flat_map(|r| &r.issues).filter(|i| i.severity == Severity::Critical).count();
    let high =
      filtered.iter().flat_map(|r| &r.issues).filter(|i| i.severity == Severity::High).count();
    let medium =
      filtered.iter().flat_map(|r| &r.issues).filter(|i| i.severity == Severity::Medium).count();
    let low =
      filtered.iter().flat_map(|r| &r.issues).filter(|i| i.severity == Severity::Low).count();

    println!(
      "Found {} issues ({} critical, {} high, {} medium, {} low)",
      total_issues.to_string().bold(),
      critical.to_string().red(),
      high.to_string().yellow(),
      medium,
      low
    );
  }

  fn print_untrusted_packages(&self, trust_scores: &[(String, TrustScore, DependencyType)]) {
    if trust_scores.is_empty() {
      return;
    }

    println!();
    println!("{}", "⚠️  Most Untrusted Packages:".yellow().bold());

    for (package, trust, dep_type) in trust_scores.iter().take(3) {
      let score_colored = if trust.score < 50.0 {
        format!("{:.0}", trust.score).red()
      } else if trust.score < 70.0 {
        format!("{:.0}", trust.score).truecolor(255, 165, 0)
      } else if trust.score < 90.0 {
        format!("{:.0}", trust.score).yellow()
      } else {
        format!("{:.0}", trust.score).green()
      };

      println!(
        "  {} ({}) - Trust Score: {} ({}) - {} critical, {} high, {} medium, {} low",
        package.cyan(),
        dependency_type_display(*dep_type),
        score_colored,
        trust_level_colored(trust.score),
        trust.critical_count.to_string().red(),
        trust.high_count.to_string().yellow(),
        trust.medium_count,
        trust.low_count
      );
    }
  }

  fn print_deduplication_candidates(&self, filtered: &[AnalysisResult]) {
    let mut packages_by_name: std::collections::HashMap<String, Vec<String>> =
      std::collections::HashMap::new();

    for result in filtered {
      if let Some(pkg) = &result.package {
        let version = result.version.clone().unwrap_or_else(|| "unknown".to_string());
        packages_by_name.entry(pkg.clone()).or_default().push(version);
      }
    }

    let dedup_candidates: Vec<_> = packages_by_name
      .iter()
      .filter_map(|(name, versions)| {
        if versions.len() > 1 {
          let mut unique_versions = versions.clone();
          unique_versions.sort();
          unique_versions.dedup();
          if unique_versions.len() > 1 {
            Some((name.clone(), unique_versions))
          } else {
            None
          }
        } else {
          None
        }
      })
      .collect();

    if dedup_candidates.is_empty() {
      return;
    }

    println!();
    println!("{}", "💡 Deduplication Possibilities:".blue().bold());
    println!("{}", "  The following packages appear in multiple versions:".dimmed());

    for (name, versions) in dedup_candidates {
      println!("  {} - versions: {}", name.cyan(), versions.join(", ").yellow());
    }
  }

  pub fn has_issues_at_level(&self, results: &[AnalysisResult], level: &str) -> bool {
    let min_severity = Severity::from_str(level).unwrap_or(Severity::Low);

    results.iter().any(|r| r.issues.iter().any(|i| i.severity >= min_severity))
  }
}

impl Default for Reporter {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::analyzers::Issue;

  #[test]
  fn test_has_issues_at_level() {
    let reporter = Reporter::new();

    let results = vec![AnalysisResult {
      package_path: "test-pkg".to_string(),
      package: Some("test-pkg".to_string()),
      version: Some("1.0.0".to_string()),
      issues: vec![Issue::new("test", "test issue", Severity::High, "test.js").with_line(1)],
      is_from_cache: false,
      trust_score: TrustScore::default(),
      dependency_type: DependencyType::Unknown,
      is_transient: false,
    }];

    assert!(reporter.has_issues_at_level(&results, "high"));
    assert!(reporter.has_issues_at_level(&results, "medium"));
    assert!(reporter.has_issues_at_level(&results, "low"));
    assert!(!reporter.has_issues_at_level(&results, "critical"));
  }

  #[test]
  fn test_critical_issues_match_high_level() {
    let reporter = Reporter::new();

    let results = vec![AnalysisResult {
      package_path: "test-pkg".to_string(),
      package: Some("test-pkg".to_string()),
      version: Some("1.0.0".to_string()),
      issues: vec![Issue::new("test", "critical issue", Severity::Critical, "test.js").with_line(1)],
      is_from_cache: false,
      trust_score: TrustScore::default(),
      dependency_type: DependencyType::Unknown,
      is_transient: false,
    }];

    assert!(reporter.has_issues_at_level(&results, "high"));
    assert!(reporter.has_issues_at_level(&results, "medium"));
    assert!(reporter.has_issues_at_level(&results, "low"));
    assert!(reporter.has_issues_at_level(&results, "critical"));
  }
}
