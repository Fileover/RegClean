use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};

use crate::backup::RestoreSummary;
use crate::fix::FixSummary;
use crate::model::{Category, Finding, Risk};
use crate::scan::ScanStats;

pub struct Painter {
    enabled: bool,
}

impl Painter {
    pub fn new(no_color: bool) -> Self {
        let enabled = !no_color
            && std::env::var_os("NO_COLOR").is_none()
            && io::stdout().is_terminal();
        Painter { enabled }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("{code}{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.paint("\x1b[1m", text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint("\x1b[2m", text)
    }

    pub fn green(&self, text: &str) -> String {
        self.paint("\x1b[32m", text)
    }

    pub fn yellow(&self, text: &str) -> String {
        self.paint("\x1b[33m", text)
    }

    pub fn red(&self, text: &str) -> String {
        self.paint("\x1b[31m", text)
    }

    pub fn cyan(&self, text: &str) -> String {
        self.paint("\x1b[36m", text)
    }

    pub fn risk(&self, risk: Risk, text: &str) -> String {
        match risk {
            Risk::Low => self.green(text),
            Risk::Medium => self.yellow(text),
            Risk::High => self.red(text),
        }
    }
}

pub fn print_header(mode: &str, admin: bool, painter: &Painter) {
    let privilege = if admin {
        "administrator"
    } else {
        "not elevated"
    };
    println!(
        "{} {}  {}  {}",
        painter.bold("RegClean"),
        env!("CARGO_PKG_VERSION"),
        painter.dim(mode),
        painter.dim(privilege)
    );
}

pub fn print_findings(findings: &[Finding], painter: &Painter) {
    println!();
    if findings.is_empty() {
        println!("{}", painter.green("No findings."));
        return;
    }
    for finding in findings {
        let risk = format!("{:<6}", finding.risk.label());
        println!(
            "{}  {}  {:<12} {}",
            painter.cyan(&finding.id),
            painter.risk(finding.risk, &risk),
            finding.category.slug(),
            painter.bold(&finding.location())
        );
        if !finding.detail.is_empty() {
            println!("          {}", painter.dim(&finding.detail));
        }
    }
}

pub fn print_summary(findings: &[Finding], stats: &ScanStats, painter: &Painter) {
    if findings.is_empty() {
        return;
    }
    let low = findings
        .iter()
        .filter(|finding| finding.risk == Risk::Low)
        .count();
    let medium = findings
        .iter()
        .filter(|finding| finding.risk == Risk::Medium)
        .count();
    let high = findings
        .iter()
        .filter(|finding| finding.risk == Risk::High)
        .count();

    let mut by_category: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        *by_category.entry(finding.category.slug()).or_default() += 1;
    }
    let category_text = by_category
        .iter()
        .map(|(name, count)| format!("{name} {count}"))
        .collect::<Vec<_>>()
        .join(", ");

    println!(
        "\nSummary: {} finding(s)  ({} low, {} medium, {} high)",
        painter.bold(&findings.len().to_string()),
        low,
        medium,
        high
    );
    println!("{} {}\n", painter.dim("Categories:"), category_text);

    let ignored = stats.allowlisted + stats.excluded + stats.skipped;
    if ignored > 0 {
        println!(
            "{} {} allowlisted, {} excluded, {} with no verifiable path",
            painter.dim("Ignored:"),
            stats.allowlisted,
            stats.excluded,
            stats.skipped
        );
    }
    if stats.inaccessible > 0 {
        println!(
            "{} {} (run as administrator to read all of HKLM)",
            painter.dim("Inaccessible keys:"),
            stats.inaccessible
        );
    }
}

pub fn print_fix_summary(summary: &FixSummary, painter: &Painter) {
    println!();
    if summary.planned.is_empty() {
        println!(
            "{}",
            painter.green(&format!(
                "Nothing to fix (0 of {} finding(s)). Adjust --max-risk or --only to include other items.",
                summary.considered
            ))
        );
        return;
    }
    if summary.dry_run {
        println!(
            "{} {} of {} finding(s) would be fixed; nothing was changed.",
            painter.yellow("Dry run:"),
            summary.planned.len(),
            summary.considered
        );
        return;
    }
    if summary.cancelled {
        println!(
            "{}",
            painter.yellow("Cancelled; no registry entries were removed.")
        );
        return;
    }

    println!(
        "Selected: {} of {} finding(s)",
        summary.planned.len(),
        summary.considered
    );
    if let Some(file) = &summary.backup_file {
        println!("{} {}", painter.dim("Backup file:"), file.display());
        println!("{} {}", painter.dim("Backup entries:"), summary.backed_up);
    }

    println!(
        "Removed: {}  |  failed: {}",
        painter.green(&summary.deleted.to_string()),
        if summary.failed > 0 {
            painter.red(&summary.failed.to_string())
        } else {
            summary.failed.to_string()
        }
    );
    for result in &summary.results {
        if !result.success {
            println!(
                "  {} {} {}",
                painter.red("failed"),
                result.location,
                painter.dim(&result.message)
            );
        }
    }
    if summary.deleted > 0 {
        if let Some(file) = &summary.backup_file {
            println!(
                "{} {}",
                painter.dim("To undo: regclean restore"),
                file.display()
            );
        }
    }
}

pub fn print_restore_summary(summary: &RestoreSummary, painter: &Painter) {
    println!();
    if summary.cancelled {
        println!("{}", painter.yellow("Restore cancelled."));
        return;
    }
    println!(
        "Restored: {}  |  failed: {}",
        painter.green(&summary.restored.to_string()),
        if summary.failed > 0 {
            painter.red(&summary.failed.to_string())
        } else {
            summary.failed.to_string()
        }
    );
}

pub fn print_categories(painter: &Painter) {
    println!("{}", painter.bold("Scan categories"));
    for category in Category::ALL {
        println!(
            "\n{}  {}",
            painter.cyan(category.slug()),
            painter.dim(category.label())
        );
        println!("  {}", category.description());
    }
}

pub fn print_exclusions(path: &std::path::Path, entries: &[String], painter: &Painter) {
    println!("{} {}", painter.dim("File:"), path.display());
    if entries.is_empty() {
        println!("No exclusions configured.");
    } else {
        for entry in entries {
            println!("  {entry}");
        }
    }
}

pub fn confirm(prompt: &str) -> Result<bool, String> {
    print!("{prompt} [y/N] ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("could not read the answer: {error}"))?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "s" | "sim" | "y" | "yes"))
}
