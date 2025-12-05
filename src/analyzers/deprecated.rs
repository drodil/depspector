use async_trait::async_trait;

use super::{Issue, PackageAnalyzer, PackageContext, Severity};

/// Analyzer that detects deprecated npm packages.
///
/// Checks if the package or specific version has been marked as deprecated
/// in the npm registry. Deprecated packages may have security issues,
/// be unmaintained, or have been replaced by alternatives.
pub struct DeprecatedAnalyzer;

impl DeprecatedAnalyzer {
  pub fn new() -> Self {
    Self
  }
}

impl Default for DeprecatedAnalyzer {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait]
impl PackageAnalyzer for DeprecatedAnalyzer {
  fn name(&self) -> &'static str {
    "deprecated"
  }

  fn requires_network(&self) -> bool {
    true
  }

  async fn analyze(&self, context: &PackageContext<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();

    let prefetched = match &context.prefetched {
      Some(p) => p,
      None => return issues,
    };

    let metadata = match prefetched.get_metadata(context.name, context.version).await {
      Some(m) => m,
      None => return issues,
    };

    if let Some(version_info) = metadata.versions.get(context.version) {
      if let Some(ref deprecation_msg) = version_info.deprecated {
        let message = format!(
          "Package '{}@{}' is deprecated: {}",
          context.name, context.version, deprecation_msg
        );

        let mut issue = Issue::new(
          self.name(),
          message,
          Severity::Medium,
          "package.json".to_string(),
        );
        if let Some(pkg_name) = Some(context.name) {
          issue = issue.with_package_name(pkg_name);
        }
        issues.push(issue);
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
    let analyzer = DeprecatedAnalyzer::new();
    assert_eq!(analyzer.name(), "deprecated");
  }

  #[test]
  fn test_requires_network() {
    let analyzer = DeprecatedAnalyzer::new();
    assert!(analyzer.requires_network());
  }
}
