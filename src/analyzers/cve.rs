use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::prefetch::VulnerabilityInfo;

#[derive(Default)]
pub struct CVEAnalyzer;

impl CVEAnalyzer {
  pub fn new() -> Self {
    Self
  }

  fn get_vulnerability_url(id: &str) -> String {
    let parts: Vec<&str> = id.splitn(2, '-').collect();
    if parts.len() != 2 {
      return format!("https://api.osv.dev/v1/vulns/{}", id);
    }

    let prefix = parts[0];

    match prefix {
      "CVE" => format!("https://nvd.nist.gov/vuln/detail/{}", id),
      "GHSA" => format!("https://github.com/advisories/{}", id),
      "RUSTSEC" => format!("https://rustsec.org/advisories/{}", id),
      "PYSEC" | "OSV" => format!("https://osv.dev/vulnerability/{}", id),
      "GO" => format!("https://pkg.go.dev/vuln/{}", id),
      _ => format!("https://api.osv.dev/v1/vulns/{}", id),
    }
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

      let url = Self::get_vulnerability_url(&vuln.id);
      let message = format!("{}: {}", vuln.id, summary);

      issues.push(
        Issue::new(self.name(), message, severity, "package.json")
          .with_package_name(context.name)
          .with_url(url),
      );
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

  #[test]
  fn test_ghsa_url() {
    let url = CVEAnalyzer::get_vulnerability_url("GHSA-xg73-94fp-g449");
    assert_eq!(url, "https://github.com/advisories/GHSA-xg73-94fp-g449");
  }

  #[test]
  fn test_cve_url() {
    let url = CVEAnalyzer::get_vulnerability_url("CVE-2021-3114");
    assert_eq!(url, "https://nvd.nist.gov/vuln/detail/CVE-2021-3114");
  }

  #[test]
  fn test_pysec_url() {
    let url = CVEAnalyzer::get_vulnerability_url("PYSEC-2022-28");
    assert_eq!(url, "https://osv.dev/vulnerability/PYSEC-2022-28");
  }

  #[test]
  fn test_osv_url() {
    let url = CVEAnalyzer::get_vulnerability_url("OSV-2020-584");
    assert_eq!(url, "https://osv.dev/vulnerability/OSV-2020-584");
  }

  #[test]
  fn test_rustsec_url() {
    let url = CVEAnalyzer::get_vulnerability_url("RUSTSEC-2019-0033");
    assert_eq!(url, "https://rustsec.org/advisories/RUSTSEC-2019-0033");
  }

  #[test]
  fn test_go_url() {
    let url = CVEAnalyzer::get_vulnerability_url("GO-2021-0001");
    assert_eq!(url, "https://pkg.go.dev/vuln/GO-2021-0001");
  }

  #[test]
  fn test_unknown_prefix_url() {
    let url = CVEAnalyzer::get_vulnerability_url("UNKNOWN-2021-0001");
    assert_eq!(url, "https://api.osv.dev/v1/vulns/UNKNOWN-2021-0001");
  }

  #[test]
  fn test_invalid_id_format() {
    let url = CVEAnalyzer::get_vulnerability_url("INVALID");
    assert_eq!(url, "https://api.osv.dev/v1/vulns/INVALID");
  }
}
