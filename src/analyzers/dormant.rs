use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{Issue, PackageAnalyzer, PackageContext, Severity};

#[derive(Default)]
pub struct DormantAnalyzer;

impl DormantAnalyzer {
  pub fn new() -> Self {
    Self
  }
}

#[async_trait]
impl PackageAnalyzer for DormantAnalyzer {
  fn name(&self) -> &'static str {
    "dormant"
  }

  fn requires_network(&self) -> bool {
    true
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    let dormant_config = context.config.get_analyzer_config("dormant");
    let days_threshold = dormant_config.and_then(|c| c.days_since_previous_publish).unwrap_or(365);

    let metadata = match &context.prefetched {
      Some(prefetched) => match prefetched.get_metadata(context.name, context.version).await {
        Some(m) => m,
        None => return issues,
      },
      None => return issues,
    };

    let current_date_str = match metadata.time.get(context.version) {
      Some(t) => t,
      None => return issues,
    };

    let current_date = match DateTime::parse_from_rfc3339(current_date_str) {
      Ok(d) => d.with_timezone(&Utc),
      Err(_) => return issues,
    };

    let mut versions: Vec<(String, DateTime<Utc>)> = metadata
      .time
      .iter()
      .filter(|(k, _)| *k != "modified" && *k != "created" && *k != context.version)
      .filter_map(|(k, v)| {
        DateTime::parse_from_rfc3339(v).ok().map(|d| (k.clone(), d.with_timezone(&Utc)))
      })
      .collect();

    if versions.is_empty() {
      return issues;
    }

    versions.sort_by(|a, b| b.1.cmp(&a.1));

    let previous = versions.iter().find(|(_, d)| *d < current_date);

    if let Some((prev_version, prev_date)) = previous {
      let days_since_previous = (current_date - *prev_date).num_days();

      if days_since_previous > days_threshold as i64 {
        let message = format!(
                    "Package was dormant for {} days before this update (previous: {}). Sudden update after long dormancy is suspicious.",
                    days_since_previous, prev_version
                );

        let npm_url = format!("https://www.npmjs.com/package/{}", context.name);
        issues.push(
          Issue::new(self.name(), message, Severity::High, "package.json")
            .with_package_name(context.name)
            .with_url(npm_url),
        );
      }
    }

    issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_analyzer_name() {
    let analyzer = DormantAnalyzer::new();
    assert_eq!(analyzer.name(), "dormant");
  }

  #[test]
  fn test_requires_network() {
    let analyzer = DormantAnalyzer::new();
    assert!(analyzer.requires_network());
  }
}
