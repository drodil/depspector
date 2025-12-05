use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};

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

      let npm_url = format!("https://www.npmjs.com/package/{}", context.name);
      issues.push(
        Issue::new(self.name(), message, Severity::Low, "package.json")
          .with_package_name(context.name)
          .with_url(npm_url),
      );
    }

    if let Some(ref publisher) = version_data.npm_user {
      let is_maintainer = metadata.maintainers.iter().any(|m| m.name == publisher.name);

      if !is_maintainer {
        let publisher_has_history =
          metadata.versions.iter().filter(|(v, _)| *v != context.version).any(
            |(_, version_info)| {
              version_info.npm_user.as_ref().is_some_and(|u| u.name == publisher.name)
            },
          );

        let severity = if publisher_has_history { Severity::Low } else { Severity::Medium };

        let message = format!(
          "Version published by user '{}' who is not listed as a maintainer.",
          publisher.name
        );

        let npm_url = format!("https://www.npmjs.com/package/{}", context.name);
        issues.push(
          Issue::new(self.name(), message, severity, "package.json")
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
    let analyzer = ReputationAnalyzer::new();
    assert_eq!(analyzer.name(), "reputation");
  }

  #[test]
  fn test_requires_network() {
    let analyzer = ReputationAnalyzer::new();
    assert!(analyzer.requires_network());
  }
}
