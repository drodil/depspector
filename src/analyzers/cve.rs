use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::prefetch::VulnerabilityInfo;
use crate::util::generate_issue_id;

#[derive(Default)]
pub struct CVEAnalyzer;

impl CVEAnalyzer {
  pub fn new() -> Self {
    Self
  }

  fn map_severity(&self, info: &VulnerabilityInfo) -> Severity {
    let critical_threshold = 9.0_f64;
    let high_threshold = 7.0_f64;
    let medium_threshold = 4.0_f64;

    if let (Some(ref severity_type), Some(ref score)) = (&info.severity_type, &info.score) {
      if severity_type == "CVSS_V3" {
        let score_str = score.split_whitespace().next().unwrap_or("0");
        if let Ok(score_val) = score_str.parse::<f64>() {
          if score_val >= critical_threshold {
            return Severity::Critical;
          }
          if score_val >= high_threshold {
            return Severity::High;
          }
          if score_val >= medium_threshold {
            return Severity::Medium;
          }
          return Severity::Low;
        }
      }
    }

    if let Some(ref db_sev) = info.database_severity {
      return match db_sev.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::High,
      };
    }

    Severity::High
  }
}

#[async_trait]
impl PackageAnalyzer for CVEAnalyzer {
  fn name(&self) -> &'static str {
    "cve"
  }

  fn requires_network(&self) -> bool {
    true
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    if let Some(cve_config) = context.config.get_analyzer_config("cve") {
      if cve_config.enabled == Some(false) {
        return issues;
      }
    }

    let vulns = match &context.prefetched {
      Some(prefetched) => {
        match prefetched.get_vulnerabilities(context.name, context.version).await {
          Some(v) => v,
          None => return issues,
        }
      }
      None => return issues,
    };

    for vuln in vulns {
      let severity = self.map_severity(&vuln);
      let summary =
        vuln.summary.or(vuln.details).unwrap_or_else(|| "Known vulnerability".to_string());

      let message = format!("{}: {}", vuln.id, summary);

      let id = generate_issue_id(self.name(), context.name, 0, &message);

      issues.push(Issue {
        issue_type: self.name().to_string(),
        line: 0,
        message,
        severity,
        code: None,
        analyzer: Some(self.name().to_string()),
        id: Some(id),
      });
    }

    issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_analyzer_name() {
    let analyzer = CVEAnalyzer::new();
    assert_eq!(analyzer.name(), "cve");
  }

  #[test]
  fn test_requires_network() {
    let analyzer = CVEAnalyzer::new();
    assert!(analyzer.requires_network());
  }
}
