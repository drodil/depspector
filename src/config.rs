use crate::analyzers::base64::{default_min_buffer_length_base64, Base64Config};
use crate::analyzers::buffer::{default_min_buffer_length_buffer, BufferConfig};
use crate::analyzers::cooldown::{default_hours_since_publish, CooldownConfig};
use crate::analyzers::cve::{
  default_cvss_critical, default_cvss_high, default_cvss_medium, CveConfig,
};
use crate::analyzers::dormant::{default_days_since_previous_publish, DormantConfig};
use crate::analyzers::env::{default_allowed_env_vars, EnvConfig};
use crate::analyzers::fs::FsConfig;
use crate::analyzers::ip::IpConfig;
use crate::analyzers::license::LicenseConfig;
use crate::analyzers::metadata::MetadataConfig;
use crate::analyzers::minified::{
  default_max_line_length, default_max_whitespace_ratio, default_min_code_length, MinifiedConfig,
};
use crate::analyzers::network::{default_allowed_hosts, NetworkConfig};
use crate::analyzers::obfuscation::{default_min_string_length, ObfuscationConfig};
use crate::analyzers::process::ProcessConfig;
use crate::analyzers::reputation::ReputationConfig;
use crate::analyzers::scripts::{default_allowed_commands, default_allowed_scripts, ScriptsConfig};
use crate::analyzers::typosquat::TyposquatConfig;
use napi::bindgen_prelude::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmConfig {
  #[serde(default = "default_registry")]
  pub registry: String,
  #[serde(default)]
  pub token: Option<String>,
  #[serde(default)]
  pub username: Option<String>,
  #[serde(default)]
  pub password: Option<String>,
}

impl Default for NpmConfig {
  fn default() -> Self {
    Self { registry: default_registry(), token: None, username: None, password: None }
  }
}

fn default_registry() -> String {
  "https://registry.npmjs.org".to_string()
}

// --- Analyzer Specific Configs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub struct SimpleConfig {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub severity: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Analyzers {
  #[serde(default)]
  pub scripts: ScriptsConfig,
  #[serde(default)]
  pub env: EnvConfig,
  #[serde(default)]
  pub network: NetworkConfig,
  #[serde(default)]
  pub obfuscation: ObfuscationConfig,
  #[serde(default)]
  pub buffer: BufferConfig,
  #[serde(default)]
  pub base64: Base64Config,
  #[serde(default)]
  pub cooldown: CooldownConfig,
  #[serde(default)]
  pub dormant: DormantConfig,
  #[serde(default)]
  pub ip: IpConfig,
  #[serde(default)]
  pub fs: FsConfig,
  #[serde(default)]
  pub license: LicenseConfig,
  #[serde(default)]
  pub typosquat: TyposquatConfig,
  #[serde(default)]
  pub reputation: ReputationConfig,
  #[serde(default)]
  pub eval: SimpleConfig,
  #[serde(default)]
  pub process: ProcessConfig,
  #[serde(default)]
  pub native: SimpleConfig,
  #[serde(default)]
  pub minified: MinifiedConfig,
  #[serde(default)]
  pub pollution: SimpleConfig,
  #[serde(default)]
  pub secrets: SimpleConfig,
  #[serde(default)]
  pub deprecated: SimpleConfig,
  #[serde(default)]
  pub cve: CveConfig,
  #[serde(default)]
  pub dynamic: SimpleConfig,
  #[serde(default)]
  pub metadata: MetadataConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_provider")]
  pub provider: String,
  #[serde(default)]
  pub api_key: Option<String>,
  #[serde(default)]
  pub model: Option<String>,
  #[serde(default = "default_ai_threshold")]
  pub threshold: String,
  #[serde(default)]
  pub endpoint: Option<String>,
  #[serde(default)]
  pub max_issues: Option<usize>,
}

impl Default for AiConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      provider: default_provider(),
      api_key: None,
      model: None,
      threshold: default_ai_threshold(),
      endpoint: None,
      max_issues: None,
    }
  }
}

fn default_provider() -> String {
  "openai".to_string()
}

fn default_ai_threshold() -> String {
  "high".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
  #[serde(default)]
  pub exclude: Vec<String>,
  #[serde(default)]
  pub exclude_paths: Vec<String>,
  #[serde(default)]
  pub ignore_issues: Vec<String>,
  #[serde(default = "default_cache_dir")]
  pub cache_dir: String,
  #[serde(default = "default_report_level")]
  pub report_level: String,
  #[serde(default)]
  pub exit_with_failure_on_level: Option<String>,
  #[serde(default)]
  pub fail_fast: bool,
  #[serde(default)]
  pub include_tests: bool,
  #[serde(default)]
  pub include_dev_deps: bool,

  #[serde(default)]
  pub include_optional_deps: bool,
  #[serde(default = "default_true")]
  pub include_peer_deps: bool,
  #[serde(default)]
  pub skip_transient: bool,
  #[serde(default)]
  pub exclude_sources: bool,
  #[serde(default)]
  pub exclude_deps: bool,
  #[serde(default)]
  pub npm: NpmConfig,
  #[serde(default)]
  pub ai: AiConfig,
  #[serde(default)]
  pub analyzers: Analyzers,
  #[serde(default = "default_max_file_size")]
  pub max_file_size: usize,
  #[serde(default)]
  pub ast_timeout_ms: u64,
  #[serde(default)]
  pub cache_max_age_seconds: Option<u64>,
  #[serde(default)]
  pub interactive: bool,
}

fn default_cache_dir() -> String {
  std::env::temp_dir().join("depspector-cache").to_string_lossy().to_string()
}

fn default_report_level() -> String {
  "medium".to_string()
}

fn default_true() -> bool {
  true
}

fn default_max_file_size() -> usize {
  5 * 1024 * 1024 // 5 MB default - larger files are skipped for AST analysis
}

impl Default for Config {
  fn default() -> Self {
    Self {
      exclude: Vec::new(),
      exclude_paths: Vec::new(),
      ignore_issues: Vec::new(),
      cache_dir: default_cache_dir(),
      report_level: default_report_level(),
      exit_with_failure_on_level: None,
      fail_fast: false,
      include_tests: false,
      include_dev_deps: false,
      include_optional_deps: false,
      include_peer_deps: true,
      skip_transient: false,
      exclude_sources: false,
      exclude_deps: false,
      interactive: false,
      npm: NpmConfig::default(),
      ai: AiConfig::default(),
      analyzers: Analyzers::default(),
      max_file_size: default_max_file_size(),
      ast_timeout_ms: 0,
      cache_max_age_seconds: None,
    }
  }
}

impl Config {
  #[allow(clippy::field_reassign_with_default)]
  pub fn default_generated() -> Self {
    let mut config = Self::default();
    config.exit_with_failure_on_level = Some("critical".to_string());
    config.ai.max_issues = Some(100);
    config.analyzers = Analyzers {
      scripts: ScriptsConfig {
        enabled: Some(true),
        severity: None,
        allowed_scripts: default_allowed_scripts(),
        allowed_commands: default_allowed_commands(),
      },
      env: EnvConfig {
        enabled: Some(true),
        severity: None,
        allowed_env_vars: default_allowed_env_vars(),
      },
      network: NetworkConfig {
        enabled: Some(true),
        severity: None,
        allowed_hosts: default_allowed_hosts(),
      },
      obfuscation: ObfuscationConfig {
        enabled: Some(true),
        severity: None,
        min_string_length: default_min_string_length(),
      },
      buffer: BufferConfig {
        enabled: Some(true),
        severity: None,
        min_buffer_length: default_min_buffer_length_buffer(),
      },
      base64: Base64Config {
        enabled: Some(true),
        severity: None,
        min_buffer_length: default_min_buffer_length_base64(),
      },
      cooldown: CooldownConfig {
        enabled: Some(true),
        severity: None,
        hours_since_publish: default_hours_since_publish(),
      },
      dormant: DormantConfig {
        enabled: Some(true),
        severity: None,
        days_since_previous_publish: default_days_since_previous_publish(),
      },
      ip: IpConfig { enabled: Some(true), severity: None, allowed_ips: Vec::new() },
      fs: FsConfig { enabled: Some(true), severity: None, additional_dangerous_paths: Vec::new() },
      license: LicenseConfig {
        enabled: Some(true),
        severity: None,
        allowed_licenses: Vec::new(),
        risky_licenses: crate::analyzers::license::default_risky_licenses(),
      },
      typosquat: TyposquatConfig {
        enabled: Some(false),
        severity: None,
        popular_packages: Vec::new(),
      },
      reputation: ReputationConfig {
        enabled: Some(true),
        severity: None,
        whitelisted_users: Vec::new(),
      },
      eval: SimpleConfig { enabled: Some(true), severity: None },
      process: ProcessConfig { enabled: Some(true), severity: None, allowed_commands: Vec::new() },
      native: SimpleConfig { enabled: Some(true), severity: None },
      minified: MinifiedConfig {
        enabled: Some(true),
        severity: None,
        max_line_length: default_max_line_length(),
        min_code_length: default_min_code_length(),
        max_whitespace_ratio: default_max_whitespace_ratio(),
      },
      pollution: SimpleConfig { enabled: Some(true), severity: None },
      secrets: SimpleConfig { enabled: Some(true), severity: None },
      deprecated: SimpleConfig { enabled: Some(true), severity: None },
      cve: CveConfig {
        enabled: Some(true),
        severity: None,
        cvss_critical: default_cvss_critical(),
        cvss_high: default_cvss_high(),
        cvss_medium: default_cvss_medium(),
      },
      dynamic: SimpleConfig { enabled: Some(false), severity: None },
      metadata: MetadataConfig { enabled: Some(false), severity: None },
    };
    config
  }
  pub fn load(config_path: Option<&Path>, cwd: Option<&Path>) -> Result<Self> {
    use napi::Error as NapiError;

    let mut config = Config::default();

    if let Some(path) = config_path {
      if path.exists() {
        let content = fs::read_to_string(path)?;
        let loaded: Config = serde_json::from_str(&content)
          .map_err(|e| NapiError::from_reason(format!("Config parse error: {}", e)))?;
        config.merge(loaded);
        return Ok(config);
      }
    }

    let default_paths = [".depspectorrc", ".depspectorrc.json", "depspector.config.json"];
    let base_dir = cwd.unwrap_or_else(|| Path::new("."));

    for name in &default_paths {
      let path = base_dir.join(name);
      if path.exists() {
        let content = fs::read_to_string(&path)?;
        let loaded: Config = serde_json::from_str(&content)
          .map_err(|e| NapiError::from_reason(format!("Config parse error: {}", e)))?;
        config.merge(loaded);
        return Ok(config);
      }
    }

    let package_json_path = base_dir.join("package.json");
    if package_json_path.exists() {
      let content = fs::read_to_string(&package_json_path)?;
      match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(json) => {
          if let Some(config_val) = json.get("depspector") {
            let loaded: Config = serde_json::from_value(config_val.clone()).map_err(|e| {
              NapiError::from_reason(format!("Config parse error in package.json: {}", e))
            })?;
            config.merge(loaded);
            return Ok(config);
          }
        }
        Err(e) => return Err(NapiError::from_reason(format!("package.json parse error: {}", e))),
      }
    }

    Ok(config)
  }

  pub fn merge(&mut self, other: Config) {
    if !other.exclude.is_empty() {
      self.exclude = other.exclude;
    }
    if !other.exclude_paths.is_empty() {
      self.exclude_paths = other.exclude_paths;
    }
    if !other.ignore_issues.is_empty() {
      self.ignore_issues = other.ignore_issues;
    }
    if other.cache_dir != default_cache_dir() {
      self.cache_dir = other.cache_dir;
    }
    if other.report_level != default_report_level() {
      self.report_level = other.report_level;
    }
    if other.exit_with_failure_on_level.is_some() {
      self.exit_with_failure_on_level = other.exit_with_failure_on_level;
    }
    if other.fail_fast {
      self.fail_fast = true;
    }
    if other.include_tests {
      self.include_tests = true;
    }
    if other.include_dev_deps {
      self.include_dev_deps = true;
    }
    if other.include_optional_deps {
      self.include_optional_deps = true;
    }
    if !other.include_peer_deps {
      self.include_peer_deps = false;
    }
    if other.skip_transient {
      self.skip_transient = true;
    }
    if other.exclude_sources {
      self.exclude_sources = true;
    }
    if other.exclude_deps {
      self.exclude_deps = true;
    }
    if other.interactive {
      self.interactive = true;
    }

    self.npm = other.npm;
    self.ai = other.ai;

    macro_rules! merge_simple {
      ($name:ident) => {
        if let Some(enabled) = other.analyzers.$name.enabled {
          self.analyzers.$name.enabled = Some(enabled);
        }
        if let Some(severity) = other.analyzers.$name.severity {
          self.analyzers.$name.severity = Some(severity);
        }
      };
    }

    merge_simple!(eval);
    if let Some(enabled) = other.analyzers.process.enabled {
      self.analyzers.process.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.process.severity {
      self.analyzers.process.severity = Some(severity);
    }
    if !other.analyzers.process.allowed_commands.is_empty() {
      self.analyzers.process.allowed_commands = other.analyzers.process.allowed_commands;
    }
    merge_simple!(native);
    if let Some(enabled) = other.analyzers.minified.enabled {
      self.analyzers.minified.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.minified.severity {
      self.analyzers.minified.severity = Some(severity);
    }
    if other.analyzers.minified.max_line_length != default_max_line_length() {
      self.analyzers.minified.max_line_length = other.analyzers.minified.max_line_length;
    }
    if other.analyzers.minified.min_code_length != default_min_code_length() {
      self.analyzers.minified.min_code_length = other.analyzers.minified.min_code_length;
    }
    if (other.analyzers.minified.max_whitespace_ratio - default_max_whitespace_ratio()).abs()
      > f64::EPSILON
    {
      self.analyzers.minified.max_whitespace_ratio = other.analyzers.minified.max_whitespace_ratio;
    }
    merge_simple!(pollution);
    merge_simple!(secrets);
    merge_simple!(deprecated);
    if let Some(enabled) = other.analyzers.cve.enabled {
      self.analyzers.cve.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.cve.severity {
      self.analyzers.cve.severity = Some(severity);
    }
    if other.analyzers.cve.cvss_critical != default_cvss_critical() {
      self.analyzers.cve.cvss_critical = other.analyzers.cve.cvss_critical;
    }
    if other.analyzers.cve.cvss_high != default_cvss_high() {
      self.analyzers.cve.cvss_high = other.analyzers.cve.cvss_high;
    }
    if other.analyzers.cve.cvss_medium != default_cvss_medium() {
      self.analyzers.cve.cvss_medium = other.analyzers.cve.cvss_medium;
    }
    merge_simple!(dynamic);
    merge_simple!(metadata);

    // Merge complex configs
    if let Some(enabled) = other.analyzers.scripts.enabled {
      self.analyzers.scripts.enabled = Some(enabled);
    }

    if let Some(severity) = other.analyzers.scripts.severity {
      self.analyzers.scripts.severity = Some(severity);
    }
    if !other.analyzers.scripts.allowed_scripts.is_empty()
      && other.analyzers.scripts.allowed_scripts != default_allowed_scripts()
    {
      self.analyzers.scripts.allowed_scripts = other.analyzers.scripts.allowed_scripts;
    }
    if !other.analyzers.scripts.allowed_commands.is_empty()
      && other.analyzers.scripts.allowed_commands != default_allowed_commands()
    {
      self.analyzers.scripts.allowed_commands = other.analyzers.scripts.allowed_commands;
    }
    if let Some(severity) = other.analyzers.env.severity {
      self.analyzers.env.severity = Some(severity);
    }
    if !other.analyzers.env.allowed_env_vars.is_empty()
      && other.analyzers.env.allowed_env_vars != default_allowed_env_vars()
    {
      self.analyzers.env.allowed_env_vars = other.analyzers.env.allowed_env_vars;
    }

    if let Some(enabled) = other.analyzers.network.enabled {
      self.analyzers.network.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.network.severity {
      self.analyzers.network.severity = Some(severity);
    }
    if !other.analyzers.network.allowed_hosts.is_empty()
      && other.analyzers.network.allowed_hosts != default_allowed_hosts()
    {
      self.analyzers.network.allowed_hosts = other.analyzers.network.allowed_hosts;
    }

    if let Some(enabled) = other.analyzers.obfuscation.enabled {
      self.analyzers.obfuscation.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.obfuscation.severity {
      self.analyzers.obfuscation.severity = Some(severity);
    }
    if other.analyzers.obfuscation.min_string_length != default_min_string_length() {
      self.analyzers.obfuscation.min_string_length = other.analyzers.obfuscation.min_string_length;
    }

    if let Some(enabled) = other.analyzers.buffer.enabled {
      self.analyzers.buffer.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.buffer.severity {
      self.analyzers.buffer.severity = Some(severity);
    }
    if other.analyzers.buffer.min_buffer_length != default_min_buffer_length_buffer() {
      self.analyzers.buffer.min_buffer_length = other.analyzers.buffer.min_buffer_length;
    }

    if let Some(enabled) = other.analyzers.base64.enabled {
      self.analyzers.base64.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.base64.severity {
      self.analyzers.base64.severity = Some(severity);
    }
    if other.analyzers.base64.min_buffer_length != default_min_buffer_length_base64() {
      self.analyzers.base64.min_buffer_length = other.analyzers.base64.min_buffer_length;
    }

    if let Some(enabled) = other.analyzers.cooldown.enabled {
      self.analyzers.cooldown.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.cooldown.severity {
      self.analyzers.cooldown.severity = Some(severity);
    }
    if other.analyzers.cooldown.hours_since_publish != default_hours_since_publish() {
      self.analyzers.cooldown.hours_since_publish = other.analyzers.cooldown.hours_since_publish;
    }

    if let Some(enabled) = other.analyzers.dormant.enabled {
      self.analyzers.dormant.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.dormant.severity {
      self.analyzers.dormant.severity = Some(severity);
    }
    if other.analyzers.dormant.days_since_previous_publish != default_days_since_previous_publish()
    {
      self.analyzers.dormant.days_since_previous_publish =
        other.analyzers.dormant.days_since_previous_publish;
    }

    if let Some(enabled) = other.analyzers.ip.enabled {
      self.analyzers.ip.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.ip.severity {
      self.analyzers.ip.severity = Some(severity);
    }
    if !other.analyzers.ip.allowed_ips.is_empty() {
      self.analyzers.ip.allowed_ips = other.analyzers.ip.allowed_ips;
    }

    if let Some(enabled) = other.analyzers.fs.enabled {
      self.analyzers.fs.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.fs.severity {
      self.analyzers.fs.severity = Some(severity);
    }
    if !other.analyzers.fs.additional_dangerous_paths.is_empty() {
      self.analyzers.fs.additional_dangerous_paths = other.analyzers.fs.additional_dangerous_paths;
    }

    if let Some(enabled) = other.analyzers.license.enabled {
      self.analyzers.license.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.license.severity {
      self.analyzers.license.severity = Some(severity);
    }
    if !other.analyzers.license.allowed_licenses.is_empty() {
      self.analyzers.license.allowed_licenses = other.analyzers.license.allowed_licenses;
    }

    if let Some(enabled) = other.analyzers.typosquat.enabled {
      self.analyzers.typosquat.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.typosquat.severity {
      self.analyzers.typosquat.severity = Some(severity);
    }
    if !other.analyzers.typosquat.popular_packages.is_empty() {
      self.analyzers.typosquat.popular_packages = other.analyzers.typosquat.popular_packages;
    }

    if let Some(enabled) = other.analyzers.reputation.enabled {
      self.analyzers.reputation.enabled = Some(enabled);
    }
    if let Some(severity) = other.analyzers.reputation.severity {
      self.analyzers.reputation.severity = Some(severity);
    }
    if !other.analyzers.reputation.whitelisted_users.is_empty() {
      self.analyzers.reputation.whitelisted_users = other.analyzers.reputation.whitelisted_users;
    }

    if other.max_file_size != default_max_file_size() {
      self.max_file_size = other.max_file_size;
    }
    if other.ast_timeout_ms != 0 {
      self.ast_timeout_ms = other.ast_timeout_ms;
    }
    if other.cache_max_age_seconds.is_some() {
      self.cache_max_age_seconds = other.cache_max_age_seconds;
    }
  }

  pub fn is_analyzer_enabled(&self, name: &str) -> bool {
    match name {
      "base64" => self.analyzers.base64.enabled.unwrap_or(true),
      "buffer" => self.analyzers.buffer.enabled.unwrap_or(true),
      "cooldown" => self.analyzers.cooldown.enabled.unwrap_or(true),
      "cve" => self.analyzers.cve.enabled.unwrap_or(true),
      "deprecated" => self.analyzers.deprecated.enabled.unwrap_or(true),
      "dormant" => self.analyzers.dormant.enabled.unwrap_or(true),
      "dynamic" => self.analyzers.dynamic.enabled.unwrap_or(false),
      "env" => self.analyzers.env.enabled.unwrap_or(true),
      "eval" => self.analyzers.eval.enabled.unwrap_or(true),
      "fs" => self.analyzers.fs.enabled.unwrap_or(true),
      "ip" => self.analyzers.ip.enabled.unwrap_or(true),
      "license" => self.analyzers.license.enabled.unwrap_or(true),
      "metadata" => self.analyzers.metadata.enabled.unwrap_or(false),
      "minified" => self.analyzers.minified.enabled.unwrap_or(true),
      "native" => self.analyzers.native.enabled.unwrap_or(true),
      "network" => self.analyzers.network.enabled.unwrap_or(true),
      "obfuscation" => self.analyzers.obfuscation.enabled.unwrap_or(true),
      "pollution" => self.analyzers.pollution.enabled.unwrap_or(true),
      "process" => self.analyzers.process.enabled.unwrap_or(true),
      "reputation" => self.analyzers.reputation.enabled.unwrap_or(true),
      "scripts" => self.analyzers.scripts.enabled.unwrap_or(true),
      "secrets" => self.analyzers.secrets.enabled.unwrap_or(true),
      "typosquat" => self.analyzers.typosquat.enabled.unwrap_or(false),
      _ => true,
    }
  }

  pub fn get_analyzer_severity(&self, name: &str) -> Option<&str> {
    match name {
      "base64" => self.analyzers.base64.severity.as_deref(),
      "buffer" => self.analyzers.buffer.severity.as_deref(),
      "cooldown" => self.analyzers.cooldown.severity.as_deref(),
      "cve" => self.analyzers.cve.severity.as_deref(),
      "deprecated" => self.analyzers.deprecated.severity.as_deref(),
      "dormant" => self.analyzers.dormant.severity.as_deref(),
      "dynamic" => self.analyzers.dynamic.severity.as_deref(),
      "env" => self.analyzers.env.severity.as_deref(),
      "eval" => self.analyzers.eval.severity.as_deref(),
      "fs" => self.analyzers.fs.severity.as_deref(),
      "ip" => self.analyzers.ip.severity.as_deref(),
      "license" => self.analyzers.license.severity.as_deref(),
      "metadata" => self.analyzers.metadata.severity.as_deref(),
      "minified" => self.analyzers.minified.severity.as_deref(),
      "native" => self.analyzers.native.severity.as_deref(),
      "network" => self.analyzers.network.severity.as_deref(),
      "obfuscation" => self.analyzers.obfuscation.severity.as_deref(),
      "pollution" => self.analyzers.pollution.severity.as_deref(),
      "process" => self.analyzers.process.severity.as_deref(),
      "reputation" => self.analyzers.reputation.severity.as_deref(),
      "scripts" => self.analyzers.scripts.severity.as_deref(),
      "secrets" => self.analyzers.secrets.severity.as_deref(),
      "typosquat" => self.analyzers.typosquat.severity.as_deref(),
      _ => None,
    }
  }
}

pub fn add_ignore_rule(issue_id: &str, cwd: Option<&std::path::Path>) -> napi::Result<()> {
  use serde_json::json;
  use std::fs;

  let base_dir = cwd.unwrap_or_else(|| std::path::Path::new("."));

  let package_json_path = base_dir.join("package.json");
  if package_json_path.exists() {
    if let Ok(content) = fs::read_to_string(&package_json_path) {
      if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
        if json.get("depspector").is_some() {
          let should_save =
            if let Some(obj) = json.get_mut("depspector").and_then(|v| v.as_object_mut()) {
              let ignore_list = obj.entry("ignoreIssues").or_insert(json!([])).as_array_mut();
              if let Some(ignore_list) = ignore_list {
                let id_val = serde_json::Value::String(issue_id.to_string());
                if !ignore_list.contains(&id_val) {
                  ignore_list.push(id_val);
                  true
                } else {
                  return Ok(());
                }
              } else {
                false
              }
            } else {
              false
            };

          if should_save {
            if let Ok(new_content) = serde_json::to_string_pretty(&json) {
              let _ = fs::write(&package_json_path, new_content);
              return Ok(());
            }
          }
        }
      }
    }
  }

  let default_paths = [".depspectorrc", ".depspectorrc.json", "depspector.config.json"];
  for name in &default_paths {
    let path = base_dir.join(name);
    if path.exists() {
      if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
          let mut should_save = false;
          let ignore_list = json.get_mut("ignoreIssues");
          if let Some(list) = ignore_list {
            if let Some(arr) = list.as_array_mut() {
              let id_val = serde_json::Value::String(issue_id.to_string());
              if !arr.contains(&id_val) {
                arr.push(id_val);
                should_save = true;
              } else {
                return Ok(());
              }
            }
          } else if let Some(obj) = json.as_object_mut() {
            obj.insert("ignoreIssues".to_string(), json!([issue_id]));
            should_save = true;
          }

          if should_save {
            if let Ok(new_content) = serde_json::to_string_pretty(&json) {
              let _ = fs::write(&path, new_content);
              return Ok(());
            }
          }
          return Ok(());
        }
      }
    }
  }

  let new_config = json!({
      "ignoreIssues": [issue_id]
  });
  let path = base_dir.join(".depspectorrc");
  if let Ok(content) = serde_json::to_string_pretty(&new_config) {
    let _ = fs::write(&path, content);
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_default_config() {
    let config = Config::default();
    assert!(config.exclude.is_empty());
    assert!(config.ignore_issues.is_empty());
    assert_eq!(config.report_level, "medium");
    assert!(!config.include_tests);
    assert!(!config.include_dev_deps);
    assert!(!config.skip_transient);
  }

  #[test]
  fn test_analyzer_enabled_default() {
    let config = Config::default();
    assert!(config.is_analyzer_enabled("buffer"));
  }

  #[test]
  fn test_parse_config() {
    let json = r#"{
            "exclude": ["test-pkg"],
            "ignoreIssues": ["abc123"],
            "reportLevel": "high",
            "analyzers": {
                "buffer": {
                    "enabled": false,
                    "minBufferLength": 100
                }
            }
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.exclude, vec!["test-pkg"]);
    assert_eq!(config.ignore_issues, vec!["abc123"]);
    assert_eq!(config.report_level, "high");
    assert!(!config.is_analyzer_enabled("buffer"));
  }

  #[test]
  fn test_npm_config_default() {
    let config = Config::default();
    assert_eq!(config.npm.registry, "https://registry.npmjs.org");
    assert!(config.npm.token.is_none());
    assert!(config.npm.username.is_none());
    assert!(config.npm.password.is_none());
  }

  #[test]
  fn test_parse_npm_config() {
    let json = r#"{
            "npm": {
                "registry": "https://custom.registry.com",
                "token": "secret-token"
            }
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.npm.registry, "https://custom.registry.com");
    assert_eq!(config.npm.token, Some("secret-token".to_string()));
  }

  #[test]
  fn test_parse_npm_basic_auth() {
    let json = r#"{
            "npm": {
                "registry": "https://private.registry.com",
                "username": "myuser",
                "password": "mypass"
            }
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.npm.registry, "https://private.registry.com");
    assert_eq!(config.npm.username, Some("myuser".to_string()));
    assert_eq!(config.npm.password, Some("mypass".to_string()));
  }

  #[test]
  fn test_parse_include_dev_deps() {
    let json = r#"{
            "includeDevDeps": false
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert!(!config.include_dev_deps);
  }

  #[test]
  fn test_parse_include_tests() {
    let json = r#"{
            "includeTests": true
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert!(config.include_tests);
  }

  #[test]
  fn test_parse_skip_transient() {
    let json = r#"{
            "skipTransient": true
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert!(config.skip_transient);
  }

  #[test]
  fn test_parse_include_optional_deps() {
    let json = r#"{
            "includeOptionalDeps": true
        }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert!(config.include_optional_deps);
  }
  #[test]
  fn test_config_merge() {
    let mut config = Config::default();
    config.report_level = "low".to_string(); // override default "medium"

    let other = Config {
      report_level: "high".to_string(),
      exclude: vec!["foo".to_string()],
      npm: NpmConfig { registry: "https://merge.registry.com".to_string(), ..NpmConfig::default() },
      ..Config::default()
    };

    config.merge(other);

    assert_eq!(config.report_level, "high");
    assert_eq!(config.exclude, vec!["foo".to_string()]);
    // Checks that npm config is replaced
    assert_eq!(config.npm.registry, "https://merge.registry.com");
  }
}
