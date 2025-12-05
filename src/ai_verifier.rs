use crate::analyzers::{AnalysisResult, Severity};
use crate::benchmark::BenchmarkCollector;
use crate::config::AiConfig;
use futures::stream::{self, StreamExt};
use log::{debug, error, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

const DEFAULT_MAX_BATCH_CHARS: usize = 50000;

#[derive(Debug, Serialize)]
struct PromptIssue {
  id: String,
  package: String,
  analyzer: String,
  message: String,
  file: String,
  code: String,
  #[serde(skip)]
  severity: Severity,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
  results: Vec<IssueResult>,
}

#[derive(Debug, Deserialize)]
struct IssueResult {
  id: String,
  is_false_positive: bool,
  reason: Option<String>,
  confidence: Option<f32>,
}

pub struct AiVerifier {
  config: AiConfig,
  client: Client,
  benchmark_collector: Option<BenchmarkCollector>,
}

impl AiVerifier {
  pub fn new(config: AiConfig) -> Self {
    let client = Client::builder()
      .pool_max_idle_per_host(10)
      .pool_idle_timeout(std::time::Duration::from_secs(60))
      .timeout(std::time::Duration::from_secs(60))
      .build()
      .unwrap_or_else(|_| Client::new());
    Self { config, client, benchmark_collector: None }
  }

  pub fn with_benchmark(mut self, collector: Option<BenchmarkCollector>) -> Self {
    self.benchmark_collector = collector;
    self
  }

  pub async fn verify(&self, mut results: Vec<AnalysisResult>) -> Vec<AnalysisResult> {
    let start_time = std::time::Instant::now();
    let mut total_processed: usize = 0;

    if !self.config.enabled {
      return results;
    }

    let api_key = if let Some(key) = &self.config.api_key {
      key.clone()
    } else if let Ok(env_key) = std::env::var("OPENAI_API_KEY") {
      env_key
    } else if let Ok(env_key) = std::env::var("GEMINI_API_KEY") {
      env_key
    } else {
      warn!("AI verification enabled but no API key found. Skipping.");
      return results;
    };

    let threshold = Severity::from_str(&self.config.threshold).unwrap_or(Severity::High);

    let mut candidates = Vec::new();

    for result in &results {
      for issue in &result.issues {
        if issue.severity < threshold {
          continue;
        }

        let context = self.get_context(&result.package_path, &issue.file, issue.line);
        let code_snippet = if !context.is_empty() {
          context
        } else if let Some(code) = &issue.code {
          code.clone()
        } else {
          continue;
        };

        candidates.push(PromptIssue {
          id: issue.get_id(),
          package: result.package.clone().unwrap_or_else(|| "unknown".to_string()),
          analyzer: issue.analyzer.clone(),
          message: issue.message.clone(),
          file: issue.file.clone(),
          code: code_snippet,
          severity: issue.severity,
        });
      }
    }

    if candidates.is_empty() {
      return results;
    }

    candidates.sort_by(|a, b| b.severity.cmp(&a.severity));

    if let Some(max) = self.config.max_issues {
      if candidates.len() > max {
        candidates.truncate(max);
      }
    }

    let mut batches = Vec::new();
    let mut current_batch = Vec::new();
    let mut current_chars = 0;
    let max_batch_chars = self.get_max_batch_chars();

    for candidate in candidates {
      let entry_len = candidate.code.len() + 200;

      if current_chars + entry_len > max_batch_chars && !current_batch.is_empty() {
        batches.push(current_batch);
        current_batch = Vec::new();
        current_chars = 0;
      }

      current_chars += entry_len;
      current_batch.push(candidate);
    }

    if !current_batch.is_empty() {
      batches.push(current_batch);
    }

    let total_batches = batches.len();
    debug!(
      "Debugging AI verifier: Processing {} batches in parallel (concurrency: 5)",
      total_batches
    );

    let mut stream = stream::iter(batches)
      .map(|batch| {
        let api_key = api_key.clone();
        async move {
          let count = batch.len();
          match self.check_batch(&api_key, &batch).await {
            Ok(res) => (Some(res), count),
            Err(e) => {
              error!("Failed to process batch: {}", e);
              (None, count)
            }
          }
        }
      })
      .buffer_unordered(5);

    while let Some((batch_results, count)) = stream.next().await {
      total_processed += count;
      if let Some(issues) = batch_results {
        for res in issues {
          for analysis_result in results.iter_mut() {
            if let Some(issue) = analysis_result.issues.iter_mut().find(|i| i.get_id() == res.id) {
              issue.is_false_positive = res.is_false_positive;
              issue.ai_reason = res.reason.clone();
              issue.ai_confidence = res.confidence;
            }
          }
        }
      }
    }

    if let Some(collector) = &self.benchmark_collector {
      collector.record_analyzer("ai_verifier", start_time.elapsed(), total_processed);
    }

    results
  }

  fn get_context(&self, package_path: &str, file_path: &str, line: usize) -> String {
    let full_path = if file_path.starts_with(package_path) {
      Path::new(file_path).to_path_buf()
    } else {
      Path::new(package_path).join(file_path)
    };

    if !full_path.exists() {
      return String::new();
    }

    if let Ok(file) = File::open(full_path) {
      let reader = BufReader::new(file);
      let lines: Vec<String> = reader.lines().map(|l| l.unwrap_or_default()).collect();

      let start = line.saturating_sub(6);
      let end = (line + 5).min(lines.len());

      if start < lines.len() {
        return lines[start..end].join("\n");
      }
    }

    String::new()
  }

  async fn check_batch(
    &self,
    api_key: &str,
    batch: &[PromptIssue],
  ) -> Result<Vec<IssueResult>, String> {
    let toon_batch = serde_toon::to_string(batch).unwrap();
    let prompt = format!(
      "Analyze the following list of potentially insecure code snippets from npm packages.\n\
      For EACH item, determine if it is a FALSE POSITIVE (safe/intentional/not a vulnerability).\n\
      \n\
      Input TOON (Token-Oriented Object Notation):\n\
      ```toon\n\
      {}\n\
      ```\n\
      \n\
      Return ONLY a JSON object with a 'results' array matching the IDs:\n\
      {{ \"results\": [ {{ \"id\": \"...\", \"is_false_positive\": boolean, \"reason\": \"short reason\", \"confidence\": float (0.0-1.0) }}, ... ] }}",
      toon_batch
    );

    match self.config.provider.as_str() {
      "openai" => self.call_openai(api_key, &prompt).await,
      "gemini" => self.call_gemini(api_key, &prompt).await,
      _ => Err(format!("Unknown provider: {}", self.config.provider)),
    }
  }

  async fn call_openai(&self, api_key: &str, prompt: &str) -> Result<Vec<IssueResult>, String> {
    let model = self.config.model.as_deref().unwrap_or("gpt-4o-mini");
    let url =
      self.config.endpoint.as_deref().unwrap_or("https://api.openai.com/v1/chat/completions");

    let body = json!({
      "model": model,
      "messages": [
        {"role": "system", "content": "You are a security expert. Analyze code for vulnerabilities. Be conservative."},
        {"role": "user", "content": prompt}
      ],
      "response_format": { "type": "json_object" }
    });

    let res = self
      .client
      .post(url)
      .header("Authorization", format!("Bearer {}", api_key))
      .json(&body)
      .send()
      .await
      .map_err(|e| e.to_string())?;

    let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;

    if let Some(content) = json["choices"][0]["message"]["content"].as_str() {
      let parsed: BatchResponse = serde_json::from_str(content).map_err(|e| e.to_string())?;
      Ok(parsed.results)
    } else {
      Err("Invalid OpenAI response format".to_string())
    }
  }

  async fn call_gemini(&self, api_key: &str, prompt: &str) -> Result<Vec<IssueResult>, String> {
    let model = self.config.model.as_deref().unwrap_or("gemini-2.5-flash");
    let url =
      format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent", model);

    let body = json!({
      "contents": [{
        "parts": [{"text": prompt}]
      }],
      "generationConfig": {
          "responseMimeType": "application/json"
      }
    });

    let res = self
      .client
      .post(&url)
      .header("x-goog-api-key", api_key)
      .json(&body)
      .send()
      .await
      .map_err(|e| e.to_string())?;

    let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;

    if let Some(text) = json["candidates"][0]["content"]["parts"][0]["text"].as_str() {
      let parsed: BatchResponse = serde_json::from_str(text).map_err(|e| e.to_string())?;
      Ok(parsed.results)
    } else {
      Err(format!("Invalid Gemini response format. Response: {}", json))
    }
  }

  fn get_max_batch_chars(&self) -> usize {
    let model = self.config.model.as_deref().unwrap_or("unknown");
    match model {
      // 128k context ~ 400k chars
      "gpt-4o" | "gpt-4o-mini" | "gpt-4-turbo" => 400_000,
      // 8k context ~ 24k chars
      "gpt-4" => 24_000,
      // 16k context ~ 48k chars
      "gpt-3.5-turbo" => 48_000,
      // 1M+ context
      "gemini-1.5-flash" | "gemini-1.5-pro" | "gemini-2.5-flash" => 3_000_000,
      _ => {
        // Fallback for unknown models
        if model.starts_with("gemini-") {
          1_000_000
        } else {
          DEFAULT_MAX_BATCH_CHARS
        }
      }
    }
  }
}
