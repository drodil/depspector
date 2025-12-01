use clap::CommandFactory;
use napi::Error as NapiError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DepspectorError {
  #[error("Configuration error: {0}")]
  Config(String),

  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  #[error("JSON parse error: {0}")]
  Json(#[from] serde_json::Error),

  #[error("HTTP request error: {0}")]
  Http(#[from] reqwest::Error),

  #[error("Parse error: {0}")]
  Parse(String),

  #[error("Analysis error: {0}")]
  Analysis(String),

  #[error("Cache error: {0}")]
  Cache(String),

  #[error("Registry error: {0}")]
  Registry(String),
}

impl From<DepspectorError> for NapiError {
  fn from(err: DepspectorError) -> Self {
    NapiError::from_reason(err.to_string())
  }
}

pub fn format_cli_error<I: CommandFactory>(err: clap::Error) -> NapiError {
  let mut cmd = I::command();
  let err = err.format(&mut cmd);
  NapiError::from_reason(err.to_string())
}
