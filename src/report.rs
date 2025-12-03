use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use colored::*;

use crate::analyzers::{AnalysisResult, DependencyType, Severity, TrustScore};

const MAX_LINE_LENGTH: usize = 120;

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
}

impl<'a> ReportContext<'a> {
  pub fn new(report_level: &'a str, only_new: bool) -> Self {
    Self { report_level, only_new, json_output: None, yaml_output: None, csv_output: None }
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

    self.print_console(&filtered, min_severity);

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

    // Write header
    wtr
      .write_record(["package", "file", "line", "severity", "type", "message", "code", "id"])
      .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Write each issue as a row
    for result in results {
      let package = result.package.as_deref().unwrap_or("unknown");

      for issue in &result.issues {
        let file_path = issue.file.as_ref().unwrap_or(&result.package_path);
        let severity = match issue.severity {
          Severity::Critical => "critical",
          Severity::High => "high",
          Severity::Medium => "medium",
          Severity::Low => "low",
        };

        wtr
          .write_record([
            package,
            file_path,
            &issue.line.to_string(),
            severity,
            &issue.issue_type,
            &issue.message,
            issue.code.as_deref().unwrap_or(""),
            issue.id.as_deref().unwrap_or(""),
          ])
          .map_err(|e| std::io::Error::other(e.to_string()))?;
      }
    }

    wtr.flush()?;
    println!("{} {}", "CSV report written to:".green(), path.display());
    Ok(())
  }

  fn print_console(&self, filtered: &[AnalysisResult], min_severity: Severity) {
    if filtered.is_empty() {
      println!("{}", "✓ No issues found".green().bold());
      return;
    }

    println!("\n{}", "Security Analysis Report".bold().underline());
    println!();

    let mut by_package: std::collections::HashMap<String, Vec<&AnalysisResult>> =
      std::collections::HashMap::new();

    for result in filtered {
      let pkg = result.package.clone().unwrap_or_else(|| "unknown".to_string());
      by_package.entry(pkg).or_default().push(result);
    }

    let mut trust_scores: Vec<(&str, &TrustScore, DependencyType)> = filtered
      .iter()
      .filter_map(|r| r.package.as_ref().map(|p| (p.as_str(), &r.trust_score, r.dependency_type)))
      .collect();

    trust_scores.sort_by(|a, b| a.1.score.partial_cmp(&b.1.score).unwrap());
    trust_scores.dedup_by(|a, b| a.0 == b.0);

    for (package, results) in &by_package {
      let trust = results.first().map(|r| &r.trust_score);
      let dep_type = results.first().map(|r| r.dependency_type).unwrap_or(DependencyType::Unknown);

      let trust_display = if let Some(t) = trust {
        format!(" [Trust: {:.0} - {}]", t.score, t.trust_level())
      } else {
        String::new()
      };

      println!(
        "📦 {} ({}){}",
        package.cyan().bold(),
        dependency_type_display(dep_type),
        trust_display.dimmed()
      );

      // Issues are already deduplicated in the analyzer
      let all_issues: Vec<_> = results
        .iter()
        .flat_map(|r| r.issues.iter().map(move |i| (i, &r.package_path, r.is_from_cache)))
        .collect();

      for (issue, package_path, is_from_cache) in &all_issues {
        if issue.severity < min_severity {
          continue;
        }

        let severity_str = match issue.severity {
          Severity::Critical => "CRITICAL".red().bold(),
          Severity::High => "HIGH".red(),
          Severity::Medium => "MEDIUM".yellow(),
          Severity::Low => "LOW".white(),
        };

        let file_path = issue.file.as_ref().unwrap_or(package_path);
        let location = format!("{}:{}", file_path, issue.line);
        let location_display = if *is_from_cache {
          format!("  {} {}", "↺".dimmed(), location.dimmed())
        } else {
          format!("  {}", location)
        };

        println!(
          "{}: {} [{}] {}",
          location_display,
          severity_str,
          issue.issue_type.dimmed(),
          issue.message,
        );

        if let Some(code) = &issue.code {
          println!("      {}", truncate_line(code, MAX_LINE_LENGTH - 6).dimmed());
        }

        if let Some(id) = &issue.id {
          println!("      ID: {}", id.dimmed());
        }
      }

      println!();
    }

    let total_issues: usize = filtered.iter().map(|r| r.issues.len()).sum();
    let critical =
      filtered.iter().flat_map(|r| &r.issues).filter(|i| i.severity == Severity::Critical).count();
    let high =
      filtered.iter().flat_map(|r| &r.issues).filter(|i| i.severity == Severity::High).count();

    println!(
      "Found {} issues ({} critical, {} high)",
      total_issues.to_string().bold(),
      critical.to_string().red(),
      high.to_string().yellow()
    );

    if !trust_scores.is_empty() {
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
      issues: vec![Issue {
        issue_type: "test".to_string(),
        line: 1,
        message: "test issue".to_string(),
        severity: Severity::High,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      }],
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
      issues: vec![Issue {
        issue_type: "test".to_string(),
        line: 1,
        message: "critical issue".to_string(),
        severity: Severity::Critical,
        code: None,
        analyzer: None,
        id: None,
        file: None,
      }],
      trust_score: TrustScore::default(),
      dependency_type: DependencyType::Unknown,
      is_transient: false,
      is_from_cache: false,
    }];

    assert!(reporter.has_issues_at_level(&results, "high"));
    assert!(reporter.has_issues_at_level(&results, "medium"));
    assert!(reporter.has_issues_at_level(&results, "low"));
    assert!(reporter.has_issues_at_level(&results, "critical"));
  }
}
