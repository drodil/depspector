use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
  Direct,
  Dev,
  Optional,
  Peer,
  #[default]
  Unknown,
}

impl DependencyType {
  pub fn as_str(&self) -> &'static str {
    match self {
      DependencyType::Direct => "direct",
      DependencyType::Dev => "dev",
      DependencyType::Optional => "optional",
      DependencyType::Peer => "peer",
      DependencyType::Unknown => "unknown",
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
  package_types: HashMap<String, DependencyType>,
  root_dependencies: HashSet<String>,
  root_dev_dependencies: HashSet<String>,
  root_optional_dependencies: HashSet<String>,
  root_peer_dependencies: HashSet<String>,
}

impl DependencyGraph {
  pub fn build(cwd: &Path, node_modules_path: &Path) -> Self {
    let mut package_types: HashMap<String, DependencyType> = HashMap::new();

    let root_pkg = match Self::read_package_json(&cwd.join("package.json")) {
      Some(pkg) => pkg,
      None => return Self::default(),
    };

    // Collect root dependencies
    let mut root_deps: Vec<String> = root_pkg
      .get("dependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();

    let mut root_dev_deps: Vec<String> = root_pkg
      .get("devDependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();

    let mut root_optional_deps: Vec<String> = root_pkg
      .get("optionalDependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();

    let mut root_peer_deps: Vec<String> = root_pkg
      .get("peerDependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();

    // Collect workspace package names to exclude from dependency tracking
    let mut workspace_packages: HashSet<String> = HashSet::new();

    // Handle monorepo workspaces - collect dependencies from workspace packages
    if let Some(workspaces) = Self::get_workspace_patterns(&root_pkg) {
      for pattern in workspaces {
        for workspace_pkg in Self::find_workspace_packages(cwd, &pattern) {
          // Track workspace package names
          if let Some(name) = workspace_pkg.get("name").and_then(|v| v.as_str()) {
            workspace_packages.insert(name.to_string());
          }

          // Add workspace dependencies to root deps (they get hoisted)
          if let Some(deps) = workspace_pkg.get("dependencies").and_then(|v| v.as_object()) {
            for key in deps.keys() {
              if !root_deps.contains(key)
                && !root_dev_deps.contains(key)
                && !root_optional_deps.contains(key)
              {
                root_deps.push(key.clone());
              }
            }
          }

          // Add workspace devDependencies
          if let Some(deps) = workspace_pkg.get("devDependencies").and_then(|v| v.as_object()) {
            for key in deps.keys() {
              if !root_deps.contains(key)
                && !root_dev_deps.contains(key)
                && !root_optional_deps.contains(key)
              {
                root_dev_deps.push(key.clone());
              }
            }
          }

          // Add workspace optionalDependencies
          if let Some(deps) = workspace_pkg.get("optionalDependencies").and_then(|v| v.as_object())
          {
            for key in deps.keys() {
              if !root_deps.contains(key)
                && !root_dev_deps.contains(key)
                && !root_optional_deps.contains(key)
                && !root_peer_deps.contains(key)
              {
                root_optional_deps.push(key.clone());
              }
            }
          }

          // Add workspace peerDependencies
          if let Some(deps) = workspace_pkg.get("peerDependencies").and_then(|v| v.as_object()) {
            for key in deps.keys() {
              if !root_deps.contains(key)
                && !root_dev_deps.contains(key)
                && !root_optional_deps.contains(key)
                && !root_peer_deps.contains(key)
              {
                root_peer_deps.push(key.clone());
              }
            }
          }
        }
      }
    }

    struct PackageDeps {
      deps: Vec<String>,
      dev_deps: Vec<String>,
      optional_deps: Vec<String>,
      peer_deps: Vec<String>,
    }

    let mut all_packages: HashMap<String, PackageDeps> = HashMap::new();

    use walkdir::WalkDir;
    for entry in WalkDir::new(node_modules_path)
      .follow_links(false)
      .into_iter()
      .filter_map(|e| e.ok())
      .filter(|e| e.file_name() == "package.json")
    {
      if let Some(pkg) = Self::read_package_json(entry.path()) {
        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() {
          continue;
        }

        let deps: Vec<String> = pkg
          .get("dependencies")
          .and_then(|v| v.as_object())
          .map(|obj| obj.keys().cloned().collect())
          .unwrap_or_default();

        let dev_deps: Vec<String> = pkg
          .get("devDependencies")
          .and_then(|v| v.as_object())
          .map(|obj| obj.keys().cloned().collect())
          .unwrap_or_default();

        let optional_deps: Vec<String> = pkg
          .get("optionalDependencies")
          .and_then(|v| v.as_object())
          .map(|obj| obj.keys().cloned().collect())
          .unwrap_or_default();

        let peer_deps: Vec<String> = pkg
          .get("peerDependencies")
          .and_then(|v| v.as_object())
          .map(|obj| obj.keys().cloned().collect())
          .unwrap_or_default();

        // Merge dependencies from different versions of the same package
        all_packages
          .entry(name)
          .and_modify(|existing| {
            for dep in &deps {
              if !existing.deps.contains(dep) {
                existing.deps.push(dep.clone());
              }
            }
            for dep in &dev_deps {
              if !existing.dev_deps.contains(dep) {
                existing.dev_deps.push(dep.clone());
              }
            }
            for dep in &optional_deps {
              if !existing.optional_deps.contains(dep) {
                existing.optional_deps.push(dep.clone());
              }
            }
            for dep in &peer_deps {
              if !existing.peer_deps.contains(dep) {
                existing.peer_deps.push(dep.clone());
              }
            }
          })
          .or_insert(PackageDeps { deps, dev_deps, optional_deps, peer_deps });
      }
    }

    let mut queue: VecDeque<(String, DependencyType)> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();

    for dep in &root_deps {
      queue.push_back((dep.clone(), DependencyType::Direct));
    }

    for dep in &root_optional_deps {
      if !root_deps.contains(dep) {
        queue.push_back((dep.clone(), DependencyType::Optional));
      }
    }

    for dep in &root_dev_deps {
      if !root_deps.contains(dep) && !root_optional_deps.contains(dep) {
        queue.push_back((dep.clone(), DependencyType::Dev));
      }
    }

    // Peer dependencies: treated similar to direct dependencies, but marked as Peer
    for dep in &root_peer_deps {
      if !root_deps.contains(dep)
        && !root_optional_deps.contains(dep)
        && !root_dev_deps.contains(dep)
      {
        queue.push_back((dep.clone(), DependencyType::Peer));
      }
    }

    while let Some((pkg_name, dep_type)) = queue.pop_front() {
      if visited.contains(&pkg_name) {
        if let Some(existing_type) = package_types.get(&pkg_name) {
          // Upgrade priority: Direct > Peer > Optional > Dev
          let should_upgrade = matches!(
            (existing_type, &dep_type),
            (DependencyType::Dev, DependencyType::Direct)
              | (DependencyType::Dev, DependencyType::Optional)
              | (DependencyType::Dev, DependencyType::Peer)
              | (DependencyType::Optional, DependencyType::Direct)
              | (DependencyType::Optional, DependencyType::Peer)
              | (DependencyType::Peer, DependencyType::Direct)
          );
          if should_upgrade {
            package_types.insert(pkg_name.clone(), dep_type);
          }
        }
        continue;
      }

      visited.insert(pkg_name.clone());
      package_types.insert(pkg_name.clone(), dep_type);

      if let Some(pkg_deps) = all_packages.get(&pkg_name) {
        for dep in &pkg_deps.deps {
          if !visited.contains(dep) {
            queue.push_back((dep.clone(), dep_type));
          }
        }

        for dep in &pkg_deps.optional_deps {
          if !visited.contains(dep) {
            let child_type =
              if dep_type == DependencyType::Direct { DependencyType::Optional } else { dep_type };
            queue.push_back((dep.clone(), child_type));
          }
        }

        // Peer dependencies: inherit parent type, but mark as Peer if parent is Direct
        for dep in &pkg_deps.peer_deps {
          if !visited.contains(dep) {
            let child_type =
              if dep_type == DependencyType::Direct { DependencyType::Peer } else { dep_type };
            queue.push_back((dep.clone(), child_type));
          }
        }

        // Dev dependencies: always mark as Dev
        for dep in &pkg_deps.dev_deps {
          if !visited.contains(dep) {
            queue.push_back((dep.clone(), DependencyType::Dev));
          }
        }
      }
    }

    Self {
      package_types,
      root_dependencies: root_deps.into_iter().collect(),
      root_dev_dependencies: root_dev_deps.into_iter().collect(),
      root_optional_dependencies: root_optional_deps.into_iter().collect(),
      root_peer_dependencies: root_peer_deps.into_iter().collect(),
    }
  }

  /// Create a DependencyGraph with pre-defined types (useful for testing)
  #[cfg(test)]
  pub fn with_types(package_types: HashMap<String, DependencyType>) -> Self {
    Self {
      package_types,
      root_dependencies: HashSet::new(),
      root_dev_dependencies: HashSet::new(),
      root_optional_dependencies: HashSet::new(),
      root_peer_dependencies: HashSet::new(),
    }
  }

  fn read_package_json(path: &Path) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
  }

  /// Extract workspace patterns from package.json
  /// Supports both array format and object format with "packages" key
  fn get_workspace_patterns(root_pkg: &serde_json::Value) -> Option<Vec<String>> {
    let workspaces = root_pkg.get("workspaces")?;

    // Handle array format: "workspaces": ["packages/*", "plugins/*"]
    if let Some(arr) = workspaces.as_array() {
      return Some(arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
    }

    // Handle object format: "workspaces": { "packages": ["packages/*"] }
    if let Some(obj) = workspaces.as_object() {
      if let Some(packages) = obj.get("packages").and_then(|v| v.as_array()) {
        return Some(packages.iter().filter_map(|v| v.as_str().map(String::from)).collect());
      }
    }

    None
  }

  /// Find all workspace package.json files matching a glob pattern
  fn find_workspace_packages(cwd: &Path, pattern: &str) -> Vec<serde_json::Value> {
    let mut packages = Vec::new();

    // Convert glob pattern to a path pattern
    // e.g., "packages/*" -> find all package.json in packages/*/
    let pattern_path = cwd.join(pattern);
    let pattern_str = pattern_path.to_string_lossy();

    // Use glob to find matching directories
    if let Ok(entries) = glob::glob(&format!("{}/package.json", pattern_str)) {
      for entry in entries.flatten() {
        if let Some(pkg) = Self::read_package_json(&entry) {
          packages.push(pkg);
        }
      }
    }

    packages
  }

  pub fn get_type(&self, package_name: &str) -> DependencyType {
    self.package_types.get(package_name).copied().unwrap_or(DependencyType::Unknown)
  }

  pub fn is_dev(&self, package_name: &str) -> bool {
    self.package_types.get(package_name) == Some(&DependencyType::Dev)
  }

  pub fn count_by_type(&self, dep_type: DependencyType) -> usize {
    self.package_types.values().filter(|&&t| t == dep_type).count()
  }

  pub fn dev_count(&self) -> usize {
    self.count_by_type(DependencyType::Dev)
  }

  pub fn optional_count(&self) -> usize {
    self.count_by_type(DependencyType::Optional)
  }

  pub fn peer_count(&self) -> usize {
    self.count_by_type(DependencyType::Peer)
  }

  pub fn total_count(&self) -> usize {
    self.package_types.len()
  }

  pub fn is_direct(&self, package_name: &str) -> bool {
    self.root_dependencies.contains(package_name)
      || self.root_dev_dependencies.contains(package_name)
      || self.root_optional_dependencies.contains(package_name)
      || self.root_peer_dependencies.contains(package_name)
  }

  pub fn get_direct_type(&self, package_name: &str) -> Option<DependencyType> {
    if self.root_dependencies.contains(package_name) {
      Some(DependencyType::Direct)
    } else if self.root_dev_dependencies.contains(package_name) {
      Some(DependencyType::Dev)
    } else if self.root_optional_dependencies.contains(package_name) {
      Some(DependencyType::Optional)
    } else if self.root_peer_dependencies.contains(package_name) {
      Some(DependencyType::Peer)
    } else {
      None
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_dependency_type_display() {
    assert_eq!(DependencyType::Direct.as_str(), "direct");
    assert_eq!(DependencyType::Dev.as_str(), "dev");
    assert_eq!(DependencyType::Optional.as_str(), "optional");
    assert_eq!(DependencyType::Peer.as_str(), "peer");
    assert_eq!(DependencyType::Unknown.as_str(), "unknown");
  }

  #[test]
  fn test_is_direct_empty() {
    let graph = DependencyGraph::default();
    assert!(!graph.is_direct("any-package"));
    assert_eq!(graph.get_direct_type("any-package"), None);
  }

  #[test]
  fn test_is_direct_dependencies() {
    let mut root_deps = HashSet::new();
    root_deps.insert("lodash".to_string());
    root_deps.insert("express".to_string());
    let graph = DependencyGraph {
      package_types: HashMap::new(),
      root_dependencies: root_deps,
      root_dev_dependencies: HashSet::new(),
      root_optional_dependencies: HashSet::new(),
      root_peer_dependencies: HashSet::new(),
    };
    assert!(graph.is_direct("lodash"));
    assert!(graph.is_direct("express"));
    assert!(!graph.is_direct("unknown-pkg"));
    assert_eq!(graph.get_direct_type("lodash"), Some(DependencyType::Direct));
    assert_eq!(graph.get_direct_type("express"), Some(DependencyType::Direct));
    assert_eq!(graph.get_direct_type("unknown-pkg"), None);
  }

  #[test]
  fn test_is_direct_dev_dependencies() {
    let mut dev_deps = HashSet::new();
    dev_deps.insert("jest".to_string());
    dev_deps.insert("typescript".to_string());
    let graph = DependencyGraph {
      package_types: HashMap::new(),
      root_dependencies: HashSet::new(),
      root_dev_dependencies: dev_deps,
      root_optional_dependencies: HashSet::new(),
      root_peer_dependencies: HashSet::new(),
    };
    assert!(graph.is_direct("jest"));
    assert!(graph.is_direct("typescript"));
    assert!(!graph.is_direct("other-pkg"));
    assert_eq!(graph.get_direct_type("jest"), Some(DependencyType::Dev));
    assert_eq!(graph.get_direct_type("typescript"), Some(DependencyType::Dev));
    assert_eq!(graph.get_direct_type("other-pkg"), None);
  }

  #[test]
  fn test_is_direct_mixed() {
    let mut deps = HashSet::new();
    deps.insert("react".to_string());
    let mut dev_deps = HashSet::new();
    dev_deps.insert("vitest".to_string());
    let mut opt_deps = HashSet::new();
    opt_deps.insert("fsevents".to_string());
    let mut peer_deps = HashSet::new();
    peer_deps.insert("react-dom".to_string());
    let graph = DependencyGraph {
      package_types: HashMap::new(),
      root_dependencies: deps,
      root_dev_dependencies: dev_deps,
      root_optional_dependencies: opt_deps,
      root_peer_dependencies: peer_deps,
    };
    assert_eq!(graph.get_direct_type("react"), Some(DependencyType::Direct));
    assert_eq!(graph.get_direct_type("vitest"), Some(DependencyType::Dev));
    assert_eq!(graph.get_direct_type("fsevents"), Some(DependencyType::Optional));
    assert_eq!(graph.get_direct_type("react-dom"), Some(DependencyType::Peer));
    assert_eq!(graph.get_direct_type("some-transient"), None);
    assert!(graph.is_direct("react"));
    assert!(graph.is_direct("vitest"));
    assert!(graph.is_direct("fsevents"));
    assert!(graph.is_direct("react-dom"));
    assert!(!graph.is_direct("some-transient"));
  }

  #[test]
  fn test_dependency_graph_empty() {
    let graph = DependencyGraph::default();
    assert_eq!(graph.get_type("any-package"), DependencyType::Unknown);
    assert_eq!(graph.dev_count(), 0);
  }

  #[test]
  fn test_dependency_graph_with_types() {
    let mut package_types = HashMap::new();
    package_types.insert("jest".to_string(), DependencyType::Dev);
    package_types.insert("typescript".to_string(), DependencyType::Dev);
    package_types.insert("lodash".to_string(), DependencyType::Direct);
    let graph = DependencyGraph {
      package_types,
      root_dependencies: HashSet::new(),
      root_dev_dependencies: HashSet::new(),
      root_optional_dependencies: HashSet::new(),
      root_peer_dependencies: HashSet::new(),
    };
    assert_eq!(graph.get_type("jest"), DependencyType::Dev);
    assert_eq!(graph.get_type("typescript"), DependencyType::Dev);
    assert_eq!(graph.get_type("lodash"), DependencyType::Direct);
    assert_eq!(graph.get_type("unknown"), DependencyType::Unknown);
    assert_eq!(graph.dev_count(), 2);
  }
}
