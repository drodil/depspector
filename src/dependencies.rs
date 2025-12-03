use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Represents a discovered package (from node_modules or local workspace)
#[derive(Debug, Clone)]
pub struct PackageInfo {
  pub name: String,
  pub version: String,
  pub path: PathBuf,
  pub package_json: serde_json::Value,
  pub dependency_type: DependencyType,
  pub is_transient: bool,
  pub is_root: bool,
  pub is_local: bool,
  pub dependencies: Vec<String>,
  pub dev_dependencies: Vec<String>,
  pub optional_dependencies: Vec<String>,
  pub peer_dependencies: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
  Direct,
  Dev,
  Optional,
  Peer,
  Local,
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
      DependencyType::Local => "local",
      DependencyType::Unknown => "unknown",
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
  package_types: HashMap<String, DependencyType>,
  discovered_packages: Vec<PackageInfo>,
}

impl DependencyGraph {
  #[allow(clippy::too_many_arguments)]
  pub fn build(
    cwd: &Path,
    node_modules_path: &Path,
    include_sources: bool,
    exclude_deps: bool,
    exclude_patterns: &[String],
    include_dev_deps: bool,
    include_optional_deps: bool,
    include_peer_deps: bool,
    skip_transient: bool,
    benchmark: Option<&crate::benchmark::BenchmarkCollector>,
  ) -> Self {
    let start_time = std::time::Instant::now();
    let root_pkg = match Self::read_package_json(&cwd.join("package.json")) {
      Some(pkg) => pkg,
      None => return Self::default(),
    };

    let ws_start = std::time::Instant::now();
    let all_workspace_packages = Self::discover_workspace_packages(cwd, &root_pkg);
    let ws_duration = ws_start.elapsed();
    if let Some(b) = benchmark {
      b.record_workspace_discovery_time(ws_duration);
    }

    let nm_start = std::time::Instant::now();
    let (all_node_modules_packages, package_types) = if !exclude_deps {
      Self::discover_node_modules_packages(node_modules_path, &all_workspace_packages)
    } else {
      (Vec::new(), HashMap::new())
    };
    let nm_duration = nm_start.elapsed();
    if let Some(b) = benchmark {
      b.record_node_modules_discovery_time(nm_duration);
    }

    let mut discovered_packages = Vec::new();

    if include_sources {
      discovered_packages.extend(all_workspace_packages);
    }

    discovered_packages.extend(all_node_modules_packages.into_iter().filter(|pkg| {
      if exclude_patterns.iter().any(|e| pkg.name.contains(e)) {
        return false;
      }
      if !include_dev_deps && pkg.dependency_type == DependencyType::Dev {
        return false;
      }
      if !include_optional_deps && pkg.dependency_type == DependencyType::Optional {
        return false;
      }
      if !include_peer_deps && pkg.dependency_type == DependencyType::Peer {
        return false;
      }
      if skip_transient && pkg.is_transient {
        return false;
      }
      true
    }));

    let total_duration = start_time.elapsed();
    if let Some(b) = benchmark {
      b.record_graph_build_time(total_duration);
    }

    Self { package_types, discovered_packages }
  }

  fn discover_workspace_packages(cwd: &Path, root_pkg: &serde_json::Value) -> Vec<PackageInfo> {
    let mut all_workspace_packages = Vec::new();

    let root_name =
      root_pkg.get("name").and_then(|v| v.as_str()).unwrap_or("<local-sources>").to_string();
    let root_version =
      root_pkg.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0").to_string();
    let root_deps: Vec<String> = root_pkg
      .get("dependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();
    let root_dev_deps: Vec<String> = root_pkg
      .get("devDependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();
    let root_optional_deps: Vec<String> = root_pkg
      .get("optionalDependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();
    let root_peer_deps: Vec<String> = root_pkg
      .get("peerDependencies")
      .and_then(|v| v.as_object())
      .map(|obj| obj.keys().cloned().collect())
      .unwrap_or_default();

    all_workspace_packages.push(PackageInfo {
      name: root_name.clone(),
      version: root_version,
      path: cwd.to_path_buf(),
      package_json: root_pkg.clone(),
      dependency_type: DependencyType::Local,
      is_transient: false,
      is_root: true,
      is_local: true,
      dependencies: root_deps.clone(),
      dev_dependencies: root_dev_deps.clone(),
      optional_dependencies: root_optional_deps.clone(),
      peer_dependencies: root_peer_deps.clone(),
    });

    if let Some(workspaces) = Self::get_workspace_patterns(root_pkg) {
      for pattern in workspaces {
        let workspace_entries = Self::find_workspace_packages_with_paths(cwd, &pattern);
        for (workspace_pkg, pkg_path) in workspace_entries {
          if let Some(name) = workspace_pkg.get("name").and_then(|v| v.as_str()) {
            let version =
              workspace_pkg.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0").to_string();
            let deps: Vec<String> = workspace_pkg
              .get("dependencies")
              .and_then(|v| v.as_object())
              .map(|obj| obj.keys().cloned().collect())
              .unwrap_or_default();
            let dev_deps: Vec<String> = workspace_pkg
              .get("devDependencies")
              .and_then(|v| v.as_object())
              .map(|obj| obj.keys().cloned().collect())
              .unwrap_or_default();
            let optional_deps: Vec<String> = workspace_pkg
              .get("optionalDependencies")
              .and_then(|v| v.as_object())
              .map(|obj| obj.keys().cloned().collect())
              .unwrap_or_default();
            let peer_deps: Vec<String> = workspace_pkg
              .get("peerDependencies")
              .and_then(|v| v.as_object())
              .map(|obj| obj.keys().cloned().collect())
              .unwrap_or_default();

            all_workspace_packages.push(PackageInfo {
              name: name.to_string(),
              version,
              path: pkg_path,
              package_json: workspace_pkg,
              dependency_type: DependencyType::Local,
              is_transient: false,
              is_root: false,
              is_local: true,
              dependencies: deps,
              dev_dependencies: dev_deps,
              optional_dependencies: optional_deps,
              peer_dependencies: peer_deps,
            });
          }
        }
      }
    }

    all_workspace_packages
  }

  fn discover_node_modules_packages(
    node_modules_path: &Path,
    workspace_packages: &[PackageInfo],
  ) -> (Vec<PackageInfo>, HashMap<String, DependencyType>) {
    use walkdir::WalkDir;

    let mut all_node_modules_packages = Vec::new();

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

        if let Some(pkg_path) = entry.path().parent() {
          if pkg_path.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            s == "dist" || s == "build"
          }) {
            continue;
          }

          let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0").to_string();
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

          all_node_modules_packages.push(PackageInfo {
            name,
            version,
            path: pkg_path.to_path_buf(),
            package_json: pkg,
            dependency_type: DependencyType::Unknown,
            is_transient: true,
            is_root: false,
            is_local: false,
            dependencies: deps,
            dev_dependencies: dev_deps,
            optional_dependencies: optional_deps,
            peer_dependencies: peer_deps,
          });
        }
      }
    }

    let mut package_types: HashMap<String, DependencyType> = HashMap::new();
    let mut queue: VecDeque<(String, DependencyType)> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();

    for workspace_pkg in workspace_packages {
      for dep in &workspace_pkg.dependencies {
        queue.push_back((dep.clone(), DependencyType::Direct));
      }
      for dep in &workspace_pkg.optional_dependencies {
        if !workspace_pkg.dependencies.contains(dep) {
          queue.push_back((dep.clone(), DependencyType::Optional));
        }
      }
      for dep in &workspace_pkg.dev_dependencies {
        if !workspace_pkg.dependencies.contains(dep)
          && !workspace_pkg.optional_dependencies.contains(dep)
        {
          queue.push_back((dep.clone(), DependencyType::Dev));
        }
      }
      for dep in &workspace_pkg.peer_dependencies {
        if !workspace_pkg.dependencies.contains(dep)
          && !workspace_pkg.optional_dependencies.contains(dep)
          && !workspace_pkg.dev_dependencies.contains(dep)
        {
          queue.push_back((dep.clone(), DependencyType::Peer));
        }
      }
    }

    while let Some((pkg_name, dep_type)) = queue.pop_front() {
      if visited.contains(&pkg_name) {
        if let Some(existing_type) = package_types.get(&pkg_name) {
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

      if let Some(pkg_info) = all_node_modules_packages.iter().find(|p| p.name == pkg_name) {
        for dep in &pkg_info.dependencies {
          if !visited.contains(dep) {
            queue.push_back((dep.clone(), dep_type));
          }
        }
        for dep in &pkg_info.optional_dependencies {
          if !visited.contains(dep) {
            let child_type =
              if dep_type == DependencyType::Direct { DependencyType::Optional } else { dep_type };
            queue.push_back((dep.clone(), child_type));
          }
        }
        for dep in &pkg_info.peer_dependencies {
          if !visited.contains(dep) {
            let child_type =
              if dep_type == DependencyType::Direct { DependencyType::Peer } else { dep_type };
            queue.push_back((dep.clone(), child_type));
          }
        }
        for dep in &pkg_info.dev_dependencies {
          if !visited.contains(dep) {
            queue.push_back((dep.clone(), DependencyType::Dev));
          }
        }
      }
    }

    let mut all_deps_set: HashSet<&String> = HashSet::new();
    for workspace_pkg in workspace_packages {
      for dep in &workspace_pkg.dependencies {
        all_deps_set.insert(dep);
      }
      for dep in &workspace_pkg.dev_dependencies {
        all_deps_set.insert(dep);
      }
      for dep in &workspace_pkg.optional_dependencies {
        all_deps_set.insert(dep);
      }
      for dep in &workspace_pkg.peer_dependencies {
        all_deps_set.insert(dep);
      }
    }

    for pkg in &mut all_node_modules_packages {
      pkg.dependency_type =
        package_types.get(&pkg.name).copied().unwrap_or(DependencyType::Unknown);
      pkg.is_transient = !all_deps_set.contains(&pkg.name);
    }

    (all_node_modules_packages, package_types)
  }

  #[cfg(test)]
  pub fn with_types(package_types: HashMap<String, DependencyType>) -> Self {
    Self { package_types, discovered_packages: Vec::new() }
  }

  fn read_package_json(path: &Path) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
  }

  fn get_workspace_patterns(root_pkg: &serde_json::Value) -> Option<Vec<String>> {
    let workspaces = root_pkg.get("workspaces")?;

    if let Some(arr) = workspaces.as_array() {
      return Some(arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
    }

    if let Some(obj) = workspaces.as_object() {
      if let Some(packages) = obj.get("packages").and_then(|v| v.as_array()) {
        return Some(packages.iter().filter_map(|v| v.as_str().map(String::from)).collect());
      }
    }

    None
  }

  fn find_workspace_packages_with_paths(
    cwd: &Path,
    pattern: &str,
  ) -> Vec<(serde_json::Value, PathBuf)> {
    let mut packages = Vec::new();

    let pattern_path = cwd.join(pattern);
    let pattern_str = pattern_path.to_string_lossy();

    if let Ok(entries) = glob::glob(&format!("{}/package.json", pattern_str)) {
      for entry in entries.flatten() {
        if let Some(pkg) = Self::read_package_json(&entry) {
          if let Some(pkg_path) = entry.parent() {
            packages.push((pkg, pkg_path.to_path_buf()));
          }
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

  pub fn discovered_packages(&self) -> &[PackageInfo] {
    &self.discovered_packages
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
    assert_eq!(DependencyType::Local.as_str(), "local");
    assert_eq!(DependencyType::Unknown.as_str(), "unknown");
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
    let graph = DependencyGraph { package_types, discovered_packages: Vec::new() };
    assert_eq!(graph.get_type("jest"), DependencyType::Dev);
    assert_eq!(graph.get_type("typescript"), DependencyType::Dev);
    assert_eq!(graph.get_type("lodash"), DependencyType::Direct);
    assert_eq!(graph.get_type("unknown"), DependencyType::Unknown);
    assert_eq!(graph.dev_count(), 2);
  }
}
