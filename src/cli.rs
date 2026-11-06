use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, bail};
use chrono::{Local, SecondsFormat};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::backup::{RestoreSummary, TOOL_NAME, TOOL_VERSION};
use crate::exclusions;
use crate::fix::{self, FixOptions, FixSummary};
use crate::model::{Category, Finding, Risk};
use crate::registry;
use crate::report::{self, Painter};
use crate::scan::{self, ScanOptions};

#[derive(Parser, Debug)]
#[command(
    name = "regclean",
    version,
    about = "Safe, reversible Windows Registry cleanup",
    long_about = "Scans the registry for broken references, shows the risk of each finding, and, when fixing, writes one .reg backup for the whole cleanup before removing anything. Scanning is read-only."
)]
struct Cli {
    /// Emit JSON for the scan, fix, restore, categories, and exclude list commands.
    #[arg(long, global = true)]
    json: bool,

    /// Disable colors in the output.
    #[arg(long, global = true)]
    no_color: bool,

    /// Ignore findings whose target starts with this prefix (repeatable).
    #[arg(long = "exclude", global = true, value_name = "PREFIX")]
    excludes: Vec<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Read-only scan (default command).
    Scan(ScanArgs),
    /// Remove findings with a single .reg backup.
    Fix(FixArgs),
    /// Restore one .reg backup file.
    Restore(RestoreArgs),
    /// List the categories that are checked.
    Categories,
    /// Manage persistent exclusions.
    Exclude {
        #[command(subcommand)]
        action: ExcludeAction,
    },
}

#[derive(Args, Debug)]
struct ScanArgs {
    #[command(flatten)]
    filter: FilterArgs,

    /// Return exit code 1 when there are findings (useful in CI/scripts).
    #[arg(long)]
    fail_on_findings: bool,
}

#[derive(Args, Debug)]
struct FixArgs {
    #[command(flatten)]
    filter: FilterArgs,

    /// Apply without asking for confirmation.
    #[arg(long)]
    yes: bool,

    /// Show what would be done without writing a backup or removing anything.
    #[arg(long)]
    dry_run: bool,

    /// Directory where the backup file will be created (default: <exe>\\backup).
    #[arg(long, value_name = "DIR")]
    backup_dir: Option<PathBuf>,

    /// Maximum risk to fix (low, medium, or high).
    #[arg(long, value_enum, default_value = "medium", value_name = "RISK")]
    max_risk: Risk,

    /// Fix only these finding IDs (repeatable or comma-separated).
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    only: Vec<String>,
}

#[derive(Args, Debug)]
struct RestoreArgs {
    /// Single .reg backup file created by the fix command.
    backup: PathBuf,

    /// Apply without asking for confirmation.
    #[arg(long)]
    yes: bool,
}

#[derive(Args, Debug, Default, Clone)]
struct FilterArgs {
    /// Categories to check (repeatable or comma-separated). Default: all.
    #[arg(long, value_enum, value_delimiter = ',', value_name = "CATEGORY")]
    category: Vec<Category>,

    /// Disable the system/vendor allowlist (may produce false positives).
    #[arg(long)]
    no_allowlist: bool,
}

#[derive(Subcommand, Debug)]
enum ExcludeAction {
    /// Add a prefix to the exclusion list.
    Add { prefix: String },
    /// Remove a prefix from the list.
    Remove { prefix: String },
    /// List the current exclusions.
    List,
}

#[derive(Serialize)]
struct ScanJson<'a> {
    tool: &'static str,
    version: &'static str,
    mode: &'static str,
    scanned_at: String,
    admin: bool,
    counts: BTreeMap<&'static str, usize>,
    risk_counts: BTreeMap<&'static str, usize>,
    allowlisted: usize,
    excluded: usize,
    inaccessible: usize,
    skipped: usize,
    findings: &'a [Finding],
}

#[derive(Serialize)]
struct FixJson<'a> {
    tool: &'static str,
    version: &'static str,
    admin: bool,
    summary: &'a FixSummary,
}

#[derive(Serialize)]
struct RestoreJson<'a> {
    tool: &'static str,
    version: &'static str,
    summary: &'a RestoreSummary,
}

pub fn run() -> Result<i32> {
    let Cli {
        json,
        no_color,
        excludes: cli_excludes,
        command,
    } = Cli::parse();
    let painter = Painter::new(no_color);
    let admin = registry::is_admin();

    let mut excludes = exclusions::load();
    excludes.extend(
        cli_excludes
            .into_iter()
            .map(|prefix| prefix.trim().to_string())
            .filter(|prefix| !prefix.is_empty()),
    );

    let command = command.unwrap_or(Command::Scan(ScanArgs {
        filter: FilterArgs::default(),
        fail_on_findings: false,
    }));

    match command {
        Command::Scan(args) => run_scan(args, json, &painter, admin, excludes),
        Command::Fix(args) => run_fix(args, json, &painter, admin, excludes),
        Command::Restore(args) => run_restore(args, json, &painter, admin),
        Command::Categories => run_categories(json, &painter),
        Command::Exclude { action } => run_exclude(action, json, &painter),
    }
}

fn run_scan(
    args: ScanArgs,
    json: bool,
    painter: &Painter,
    admin: bool,
    excludes: Vec<String>,
) -> Result<i32> {
    let options = ScanOptions {
        categories: args.filter.category,
        ignore_allowlist: args.filter.no_allowlist,
        excludes,
    };
    let result = scan::scan(&options);

    if json {
        let output = ScanJson {
            tool: TOOL_NAME,
            version: TOOL_VERSION,
            mode: "scan",
            scanned_at: Local::now().to_rfc3339_opts(SecondsFormat::Secs, false),
            admin,
            counts: category_counts(&result.findings),
            risk_counts: risk_counts(&result.findings),
            allowlisted: result.stats.allowlisted,
            excluded: result.stats.excluded,
            inaccessible: result.stats.inaccessible,
            skipped: result.stats.skipped,
            findings: &result.findings,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        report::print_header("read-only scan", admin, painter);
        report::print_findings(&result.findings, painter);
        report::print_summary(&result.findings, &result.stats, painter);
    }

    if args.fail_on_findings && !result.findings.is_empty() {
        return Ok(1);
    }
    Ok(0)
}

fn run_fix(
    args: FixArgs,
    json: bool,
    painter: &Painter,
    admin: bool,
    excludes: Vec<String>,
) -> Result<i32> {
    if json && !args.yes && !args.dry_run {
        bail!("with --json, use --yes to apply fixes");
    }

    let options = ScanOptions {
        categories: args.filter.category,
        ignore_allowlist: args.filter.no_allowlist,
        excludes,
    };
    let result = scan::scan(&options);

    if !json {
        report::print_header("fix mode", admin, painter);
        report::print_findings(&result.findings, painter);
        report::print_summary(&result.findings, &result.stats, painter);
    }

    if !args.only.is_empty() {
        for id in &args.only {
            if !result
                .findings
                .iter()
                .any(|finding| finding.id.eq_ignore_ascii_case(id))
            {
                eprintln!("warning: ID '{id}' was not found in the current scan");
            }
        }
    }

    let summary = fix::run(
        &result.findings,
        &FixOptions {
            backup_root: args.backup_dir,
            assume_yes: args.yes,
            dry_run: args.dry_run,
            max_risk: args.max_risk,
            only: args.only,
            quiet: json,
        },
    )
    .map_err(anyhow::Error::msg)?;

    if json {
        let output = FixJson {
            tool: TOOL_NAME,
            version: TOOL_VERSION,
            admin,
            summary: &summary,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        report::print_fix_summary(&summary, painter);
    }

    Ok(if summary.failed > 0 { 1 } else { 0 })
}

fn run_restore(
    args: RestoreArgs,
    json: bool,
    painter: &Painter,
    admin: bool,
) -> Result<i32> {
    if json && !args.yes {
        bail!("with --json, use --yes to restore");
    }
    if !json {
        report::print_header("restore", admin, painter);
    }
    let summary = fix::restore_file(&args.backup, args.yes, json).map_err(anyhow::Error::msg)?;

    if json {
        let output = RestoreJson {
            tool: TOOL_NAME,
            version: TOOL_VERSION,
            summary: &summary,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        report::print_restore_summary(&summary, painter);
    }

    Ok(if summary.failed > 0 { 1 } else { 0 })
}

fn run_categories(json: bool, painter: &Painter) -> Result<i32> {
    #[derive(Serialize)]
    struct CategoryInfo {
        slug: &'static str,
        label: &'static str,
        description: &'static str,
    }

    if json {
        let categories: Vec<CategoryInfo> = Category::ALL
            .iter()
            .map(|category| CategoryInfo {
                slug: category.slug(),
                label: category.label(),
                description: category.description(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&categories)?);
    } else {
        report::print_categories(painter);
    }
    Ok(0)
}

fn run_exclude(action: ExcludeAction, json: bool, painter: &Painter) -> Result<i32> {
    let path = exclusions::path();
    match action {
        ExcludeAction::List => {
            let entries = exclusions::read_lines(&path)?;
            if json {
                #[derive(Serialize)]
                struct Output<'a> {
                    path: &'a std::path::Path,
                    entries: &'a [String],
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&Output {
                        path: &path,
                        entries: &entries
                    })?
                );
            } else {
                report::print_exclusions(&path, &entries, painter);
            }
        }
        ExcludeAction::Add { prefix } => {
            let prefix = prefix.trim();
            if prefix.is_empty() {
                bail!("the prefix cannot be empty");
            }
            if exclusions::add(prefix)? {
                println!("Exclusion added at {}: {prefix}", path.display());
            } else {
                println!("Exclusion already exists: {prefix}");
            }
        }
        ExcludeAction::Remove { prefix } => {
            if exclusions::remove(&prefix)? {
                println!("Exclusion removed: {}", prefix.trim());
            } else {
                println!("Exclusion not found: {}", prefix.trim());
            }
        }
    }
    Ok(0)
}

fn category_counts(findings: &[Finding]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.category.slug()).or_insert(0) += 1;
    }
    counts
}

fn risk_counts(findings: &[Finding]) -> BTreeMap<&'static str, usize> {
    [
        ("low", Risk::Low),
        ("medium", Risk::Medium),
        ("high", Risk::High),
    ]
    .into_iter()
    .map(|(label, risk)| {
        (
            label,
            findings
                .iter()
                .filter(|finding| finding.risk == risk)
                .count(),
        )
    })
    .collect()
}
