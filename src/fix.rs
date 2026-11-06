use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::backup::{self, RestoreSummary};
use crate::model::{Finding, Risk, Target};
use crate::registry;

#[derive(Debug, Clone)]
pub struct FixOptions {
    pub backup_root: Option<PathBuf>,
    pub assume_yes: bool,
    pub dry_run: bool,
    pub max_risk: Risk,
    pub only: Vec<String>,
    pub quiet: bool,
}

impl Default for FixOptions {
    fn default() -> Self {
        FixOptions {
            backup_root: None,
            assume_yes: false,
            dry_run: false,
            max_risk: Risk::Medium,
            only: Vec::new(),
            quiet: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FixResult {
    pub id: String,
    pub location: String,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixSummary {
    pub considered: usize,
    pub planned: Vec<Finding>,
    pub backup_dir: Option<PathBuf>,
    pub backup_file: Option<PathBuf>,
    pub backed_up: usize,
    pub deleted: usize,
    pub failed: usize,
    pub dry_run: bool,
    pub cancelled: bool,
    pub results: Vec<FixResult>,
}

pub fn run(findings: &[Finding], options: &FixOptions) -> Result<FixSummary, String> {
    let eligible: Vec<Finding> = findings
        .iter()
        .filter(|finding| finding.risk <= options.max_risk)
        .filter(|finding| {
            options.only.is_empty()
                || options
                    .only
                    .iter()
                    .any(|id| finding.id.eq_ignore_ascii_case(id))
        })
        .cloned()
        .collect();

    let backup_root = backup::backup_root(options.backup_root.as_deref());

    if eligible.is_empty() {
        return Ok(FixSummary {
            considered: findings.len(),
            planned: Vec::new(),
            backup_dir: None,
            backup_file: None,
            backed_up: 0,
            deleted: 0,
            failed: 0,
            dry_run: options.dry_run,
            cancelled: false,
            results: Vec::new(),
        });
    }

    if options.dry_run {
        return Ok(FixSummary {
            considered: findings.len(),
            planned: eligible,
            backup_dir: None,
            backup_file: None,
            backed_up: 0,
            deleted: 0,
            failed: 0,
            dry_run: true,
            cancelled: false,
            results: Vec::new(),
        });
    }

    if !options.assume_yes {
        if options.quiet || !std::io::stdin().is_terminal() {
            return Err("confirmation required: rerun with --yes when output is not a terminal".to_string());
        }
        let noun = if eligible.len() == 1 { "entry" } else { "entries" };
        let prompt = format!(
            "Remove {} registry {noun}? A single .reg backup will be saved in {}.",
            eligible.len(),
            backup_root.display()
        );
        if !confirm(&prompt)? {
            return Ok(FixSummary {
                considered: findings.len(),
                planned: eligible,
                backup_dir: Some(backup_root),
                backup_file: None,
                backed_up: 0,
                deleted: 0,
                failed: 0,
                dry_run: false,
                cancelled: true,
                results: Vec::new(),
            });
        }
    }

    let backup_file = backup::new_backup_file(options.backup_root.as_deref())?;
    backup::export_findings(&eligible, &backup_file)
        .map_err(|error| format!("backup failed; nothing was removed: {error}"))?;
    let backup_dir = backup_file.parent().map(Path::to_path_buf);
    let backed_up = eligible.len();

    let mut deleted = 0;
    let mut failed = 0;
    let mut results = Vec::with_capacity(eligible.len());

    for finding in &eligible {
        match delete_target(&finding.target) {
            Ok(()) => {
                deleted += 1;
                results.push(FixResult {
                    id: finding.id.clone(),
                    location: finding.location(),
                    success: true,
                    message: "deleted".to_string(),
                });
            }
            Err(error) => {
                failed += 1;
                results.push(FixResult {
                    id: finding.id.clone(),
                    location: finding.location(),
                    success: false,
                    message: error,
                });
            }
        }
    }

    Ok(FixSummary {
        considered: findings.len(),
        planned: eligible,
        backup_dir,
        backup_file: Some(backup_file),
        backed_up,
        deleted,
        failed,
        dry_run: false,
        cancelled: false,
        results,
    })
}

/// Import the single .reg file created by a cleanup, after confirmation.
pub fn restore_file(path: &Path, assume_yes: bool, quiet: bool) -> Result<RestoreSummary, String> {
    let is_reg = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("reg"));
    if !is_reg {
        return Err("restore requires the single .reg backup file".to_string());
    }
    if !path.is_file() {
        return Err(format!("backup file not found: {}", path.display()));
    }

    if !assume_yes {
        if quiet || !std::io::stdin().is_terminal() {
            return Err("confirmation required: rerun with --yes when output is not a terminal".to_string());
        }
        let prompt = format!(
            "Import {}? This may overwrite current registry values.",
            path.display()
        );
        if !confirm(&prompt)? {
            return Ok(RestoreSummary {
                restored: 0,
                failed: 0,
                cancelled: true,
            });
        }
    }

    backup::import_reg_file(path)?;
    Ok(RestoreSummary {
        restored: 1,
        failed: 0,
        cancelled: false,
    })
}

fn delete_target(target: &Target) -> Result<(), String> {
    match &target.value {
        Some(value) => registry::delete_value(target.hive, &target.path, value),
        None => registry::delete_key(target.hive, &target.path),
    }
}

fn confirm(prompt: &str) -> Result<bool, String> {
    use std::io::Write;

    print!("{prompt} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("could not flush the prompt: {error}"))?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("could not read the answer: {error}"))?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes"))
}
