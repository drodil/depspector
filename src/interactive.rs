use crate::analyzers::{AnalysisResult, Issue};
use crate::config::Config;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use napi::Result;

pub fn run_interactive(
  results: &[AnalysisResult],
  _config: &Config,
  cwd: Option<&std::path::Path>,
) -> Result<()> {
  let mut all_issues: Vec<(&Issue, String)> = Vec::new();
  for res in results {
    let pkg_name = res.package.clone().unwrap_or_else(|| "unknown".to_string());
    for issue in &res.issues {
      all_issues.push((issue, pkg_name.clone()));
    }
  }

  if all_issues.is_empty() {
    println!("{}", style("No issues found!").green());
    return Ok(());
  }

  loop {
    let options: Vec<String> = all_issues
      .iter()
      .map(|(issue, pkg)| {
        format!(
          "[{:?}] {} - {} ({})",
          issue.severity,
          pkg,
          issue.id,
          issue.message.chars().take(50).collect::<String>()
        )
      })
      .collect();

    let mut selections = options.clone();
    selections.push("Exit".to_string());

    let selection = Select::with_theme(&ColorfulTheme::default())
      .with_prompt("Select an issue to investigate")
      .default(0)
      .items(&selections)
      .interact()
      .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    if selection == options.len() {
      break;
    }

    let (issue, pkg) = &all_issues[selection];
    handle_issue_interaction(issue, pkg, cwd)?;
  }

  Ok(())
}

fn handle_issue_interaction(issue: &Issue, pkg: &str, cwd: Option<&std::path::Path>) -> Result<()> {
  let term = Term::stdout();
  term.clear_screen().ok();

  println!("\n{}", style("Issue Detail").bold().underlined());
  println!("{}: {}", style("ID").bold(), issue.id);
  println!("{}: {}", style("Package").bold(), pkg);
  println!("{}: {:?}", style("Severity").bold(), issue.severity);
  println!("{}: {}", style("Analyzer").bold(), issue.analyzer);
  println!("{}: {}", style("Message").bold(), issue.message);

  if let Some(reason) = &issue.ai_reason {
    println!("{}: {}", style("AI Analysis").bold(), reason);
    if let Some(conf) = issue.ai_confidence {
      println!("{}: {:.2}", style("AI Confidence").bold(), conf);
    }
  }

  if let Some(code) = &issue.code {
    println!("\n{}:", style("Code Snippet").bold());
    println!("--------------------------------------------------");
    println!("{}", style(code).cyan());
    println!("--------------------------------------------------");
  }

  let actions = vec!["Back to list", "Ignore this issue (add to config)", "Open file in editor"];

  loop {
    let selection = Select::with_theme(&ColorfulTheme::default())
      .with_prompt("Action")
      .items(&actions)
      .default(0)
      .interact()
      .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    match selection {
      0 => break, // Back
      1 => {
        crate::config::add_ignore_rule(&issue.id, cwd)?;
        println!("{}", style(format!("Added {} to ignored issues.", issue.id)).green());
        let _ = term.read_key();
        break;
      }
      2 => {
        if !issue.file.is_empty() {
          let _ = std::process::Command::new("code").arg(&issue.file).spawn();
          #[cfg(target_os = "macos")]
          let _ = std::process::Command::new("open").arg(&issue.file).spawn();
          #[cfg(target_os = "windows")]
          let _ = std::process::Command::new("cmd").args(["/C", "start", "", &issue.file]).spawn();
          #[cfg(target_os = "linux")]
          let _ = std::process::Command::new("xdg-open").arg(&issue.file).spawn();

          println!("Attempted to open file: {}", issue.file);
        } else {
          println!("No file path associated with this issue.");
        }
      }
      _ => {}
    }
  }
  term.clear_screen().ok();
  Ok(())
}
