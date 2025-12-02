use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};
use crate::util::generate_issue_id;

#[derive(Default)]
pub struct ReputationAnalyzer;

impl ReputationAnalyzer {
  pub fn new() -> Self {
    Self
  }
}

#[async_trait]
impl PackageAnalyzer for ReputationAnalyzer {
  fn name(&self) -> &'static str {
    "reputation"
  }

  fn requires_network(&self) -> bool {
    true
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = vec![];

    let metadata = match &context.prefetched {
      Some(prefetched) => match prefetched.get_metadata(context.name, context.version).await {
        Some(m) => m,
        None => return issues,
      },
      None => return issues,
    };

    let version_data = match metadata.versions.get(context.version) {
      Some(v) => v,
      None => return issues,
    };

    let reputation_config = context.config.get_analyzer_config("reputation");
    let whitelisted_users: Vec<String> =
      reputation_config.and_then(|c| c.whitelisted_users.clone()).unwrap_or_default();

    if let Some(ref publisher) = version_data.npm_user {
      if whitelisted_users.contains(&publisher.name) {
        return issues;
      }
    }

    if metadata.maintainers.len() == 1 {
      let message = "Package has a single maintainer.".to_string();

      let id = generate_issue_id(self.name(), context.name, 0, &message);

      issues.push(Issue {
        issue_type: self.name().to_string(),
        line: 0,
        message,
        severity: Severity::Low,
        code: None,
        analyzer: Some(self.name().to_string()),
        id: Some(id),
        file: None,
      });
    }

    if let Some(ref publisher) = version_data.npm_user {
      let is_maintainer = metadata.maintainers.iter().any(|m| m.name == publisher.name);

      if !is_maintainer {
        let message = format!(
          "Version published by user '{}' who is not listed as a maintainer.",
          publisher.name
        );

        let id = generate_issue_id(self.name(), context.name, 0, &message);

        issues.push(Issue {
          issue_type: self.name().to_string(),
          line: 0,
          message,
          severity: Severity::High,
          code: None,
          analyzer: Some(self.name().to_string()),
          id: Some(id),
          file: None,
        });
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
    let analyzer = ReputationAnalyzer::new();
    assert_eq!(analyzer.name(), "reputation");
  }

  #[test]
  fn test_requires_network() {
    let analyzer = ReputationAnalyzer::new();
    assert!(analyzer.requires_network());
  }
}
