use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{Issue, PackageAnalyzer, PackageContext, Severity};

#[derive(Default)]
pub struct CooldownAnalyzer;

impl CooldownAnalyzer {
  pub fn new() -> Self {
    Self
  }
}

#[async_trait]
impl PackageAnalyzer for CooldownAnalyzer {
  fn name(&self) -> &'static str {
    "cooldown"
  }

  fn requires_network(&self) -> bool {
    true
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    let cooldown_config = context.config.get_analyzer_config("cooldown");
    let hours_threshold = cooldown_config.and_then(|c| c.hours_since_publish).unwrap_or(72);

    let metadata = match &context.prefetched {
      Some(prefetched) => match prefetched.get_metadata(context.name, context.version).await {
        Some(m) => m,
        None => return issues,
      },
      None => return issues,
    };

    let created = match metadata.time.get(context.version) {
      Some(t) => t,
      None => return issues,
    };

    let publish_date = match DateTime::parse_from_rfc3339(created) {
      Ok(d) => d.with_timezone(&Utc),
      Err(_) => return issues,
    };

    let now = Utc::now();
    let hours_since_publish = (now - publish_date).num_hours();

    if hours_since_publish < hours_threshold as i64 {
      let message = format!(
        "Package version {} was published less than {} hours ago ({:.1}h).",
        context.version, hours_threshold, hours_since_publish as f64
      );

      let mut issue =
        Issue::new(self.name(), message, Severity::Medium, "package.json".to_string());
      if let Some(pkg_name) = Some(context.name) {
        issue = issue.with_package_name(pkg_name);
      }
      issues.push(issue);
    }

    issues
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_analyzer_name() {
    let analyzer = CooldownAnalyzer::new();
    assert_eq!(analyzer.name(), "cooldown");
  }

  #[test]
  fn test_requires_network() {
    let analyzer = CooldownAnalyzer::new();
    assert!(analyzer.requires_network());
  }
}
