use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::Duration;

use eframe::egui;
use egui::{Color32, RichText};

use crate::backup::{self, RestoreSummary};
use crate::exclusions;
use crate::fix::{self, FixOptions, FixSummary};
use crate::model::{Category, Finding, Risk};
use crate::registry;
use crate::scan::{self, ScanOptions, ScanResult, ScanStats};

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([920.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "RegClean",
        options,
        Box::new(|cc| Ok(Box::new(RegCleanApp::new(cc)) as Box<dyn eframe::App>)),
    )
}

enum JobResult {
    Scanned(ScanResult),
    Fixed(Result<FixSummary, String>),
    Restored(Result<RestoreSummary, String>),
}

#[derive(Clone)]
enum ConfirmAction {
    Fix { ids: Vec<String> },
    Restore { backup: PathBuf },
}

struct RegCleanApp {
    findings: Vec<Finding>,
    stats: Option<ScanStats>,
    selected: HashSet<String>,
    categories: HashSet<Category>,
    allowlist: bool,
    search: String,
    busy: bool,
    status: String,
    error: Option<String>,
    receiver: Option<Receiver<JobResult>>,
    confirm: Option<ConfirmAction>,
    last_fix: Option<FixSummary>,
    last_restore: Option<RestoreSummary>,
    admin: bool,
    has_scanned: bool,
}

impl RegCleanApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self {
            findings: Vec::new(),
            stats: None,
            selected: HashSet::new(),
            categories: Category::ALL.into_iter().collect(),
            allowlist: true,
            search: String::new(),
            busy: false,
            status: "Ready to scan.".to_string(),
            error: None,
            receiver: None,
            confirm: None,
            last_fix: None,
            last_restore: None,
            admin: registry::is_admin(),
            has_scanned: false,
        }
    }

    fn poll_worker(&mut self) {
        let polled = self.receiver.as_ref().map(|receiver| receiver.try_recv());
        let Some(polled) = polled else {
            return;
        };
        match polled {
            Ok(JobResult::Scanned(result)) => {
                self.receiver = None;
                self.busy = false;
                self.has_scanned = true;
                self.findings = result.findings;
                self.stats = Some(result.stats);
                self.selected = self
                    .findings
                    .iter()
                    .filter(|finding| finding.risk <= Risk::Medium)
                    .map(|finding| finding.id.clone())
                    .collect();
                self.status = if self.findings.is_empty() {
                    "No findings in the selected categories.".to_string()
                } else {
                    format!(
                        "{} finding(s); {} selected.",
                        self.findings.len(),
                        self.selected.len()
                    )
                };
                self.error = None;
            }
            Ok(JobResult::Fixed(result)) => {
                self.receiver = None;
                self.busy = false;
                match result {
                    Ok(summary) => {
                        let deleted: HashSet<String> = summary
                            .results
                            .iter()
                            .filter(|result| result.success)
                            .map(|result| result.id.clone())
                            .collect();
                        self.findings.retain(|finding| !deleted.contains(&finding.id));
                        self.selected.retain(|id| !deleted.contains(id));
                        self.status = format!(
                            "Fix complete: {} removed, {} failed; one backup contains {} entry(ies).",
                            summary.deleted, summary.failed, summary.backed_up
                        );
                        if summary.failed > 0 {
                            self.error = Some(
                                "Some entries could not be removed; see the summary below."
                                    .to_string(),
                            );
                        } else {
                            self.error = None;
                        }
                        self.last_restore = None;
                        self.last_fix = Some(summary);
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.status =
                            "The fix failed; nothing is removed without a successful backup."
                                .to_string();
                    }
                }
            }
            Ok(JobResult::Restored(result)) => {
                self.receiver = None;
                self.busy = false;
                match result {
                    Ok(summary) => {
                        self.last_fix = None;
                        self.last_restore = Some(summary.clone());
                        self.start_scan();
                        self.status = format!(
                            "Backup restored: {} entry(ies) restored, {} failed. Scanning again...",
                            summary.restored, summary.failed
                        );
                        self.error = None;
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.status = "The restore failed.".to_string();
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.receiver = None;
                self.busy = false;
                self.error = Some("The operation ended unexpectedly.".to_string());
            }
        }
    }

    fn start_scan(&mut self) {
        if self.busy {
            return;
        }
        if self.categories.is_empty() {
            self.error = Some("Select at least one category.".to_string());
            return;
        }
        let options = ScanOptions {
            categories: Category::ALL
                .iter()
                .copied()
                .filter(|category| self.categories.contains(category))
                .collect(),
            ignore_allowlist: !self.allowlist,
            excludes: exclusions::load(),
        };
        let (sender, receiver) = channel();
        self.receiver = Some(receiver);
        self.busy = true;
        self.error = None;
        self.status = "Scanning the registry...".to_string();
        std::thread::spawn(move || {
            let result = scan::scan(&options);
            let _ = sender.send(JobResult::Scanned(result));
        });
    }

    fn start_fix(&mut self, ids: Vec<String>) {
        if self.busy {
            return;
        }
        let selected: Vec<Finding> = self
            .findings
            .iter()
            .filter(|finding| {
                ids.iter()
                    .any(|id| id.eq_ignore_ascii_case(&finding.id))
            })
            .cloned()
            .collect();
        if selected.is_empty() {
            self.error = Some("No selected finding was found.".to_string());
            return;
        }
        let options = FixOptions {
            backup_root: None,
            assume_yes: true,
            dry_run: false,
            max_risk: Risk::High,
            only: ids,
            quiet: true,
        };
        let (sender, receiver) = channel();
        self.receiver = Some(receiver);
        self.busy = true;
        self.error = None;
        self.status = format!("Fixing {} entr(ies)...", selected.len());
        std::thread::spawn(move || {
            let result = fix::run(&selected, &options);
            let _ = sender.send(JobResult::Fixed(result));
        });
    }

    fn start_restore(&mut self, backup: PathBuf) {
        if self.busy {
            return;
        }
        let (sender, receiver) = channel();
        self.receiver = Some(receiver);
        self.busy = true;
        self.error = None;
        self.status = "Restoring backup...".to_string();
        std::thread::spawn(move || {
            let result = fix::restore_file(&backup, true, true);
            let _ = sender.send(JobResult::Restored(result));
        });
    }

    fn top_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("regclean_header").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("RegClean").strong());
                ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).weak());
                ui.separator();
                if self.admin {
                    ui.label(
                        RichText::new("administrator")
                            .color(Color32::from_rgb(110, 200, 130)),
                    );
                } else {
                    ui.label(
                        RichText::new("not elevated")
                            .color(Color32::from_rgb(235, 170, 70)),
                    )
                    .on_hover_text(
                        "Run as administrator to fix findings under HKLM.",
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_scan = !self.busy && !self.categories.is_empty();
                    if ui
                        .add_enabled(can_scan, egui::Button::new("Scan"))
                        .clicked()
                    {
                        self.start_scan();
                    }
                    if self.busy {
                        ui.spinner();
                    }
                });
            });
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Categories:").strong());
                for category in Category::ALL {
                    let mut checked = self.categories.contains(&category);
                    if ui
                        .checkbox(&mut checked, category.label())
                        .on_hover_text(category.description())
                        .changed()
                    {
                        if checked {
                            self.categories.insert(category);
                        } else {
                            self.categories.remove(&category);
                        }
                    }
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.allowlist, "System/vendor allowlist")
                    .on_hover_text(
                        "Ignores system paths, installer caches, and vendor folders.",
                    );
                ui.add_space(12.0);
                ui.label("Search:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search)
                        .hint_text("path, category, or detail")
                        .desired_width(360.0),
                );
                if !self.search.is_empty() && ui.button("Clear").clicked() {
                    self.search.clear();
                }
                if self.categories.is_empty() {
                    ui.colored_label(
                        Color32::from_rgb(235, 170, 70),
                        "Select at least one category.",
                    );
                }
            });
            ui.add_space(6.0);
        });
    }

    fn bottom_panel(&mut self, ui: &mut egui::Ui) {
        let selected_count = self.selected.len();
        let finding_count = self.findings.len();
        let has_scanned = self.has_scanned;
        let busy = self.busy;
        let status = self.status.clone();
        let error = self.error.clone();
        let stats = self.stats.clone();
        let last_backup = self
            .last_fix
            .as_ref()
            .and_then(|summary| summary.backup_file.clone());
        let last_fix_info = self.last_fix.as_ref().map(|summary| {
            (
                summary.deleted,
                summary.failed,
                summary.backed_up,
                summary
                    .backup_file
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "(no backup)".to_string()),
            )
        });
        let last_restore_info = self
            .last_restore
            .as_ref()
            .map(|summary| (summary.restored, summary.failed));

        egui::Panel::bottom("regclean_footer").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{selected_count} selected")).strong());
                if has_scanned {
                    ui.separator();
                    ui.label(format!("{finding_count} finding(s)"));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_fix = !busy && selected_count > 0;
                    if ui
                        .add_enabled(
                            can_fix,
                            egui::Button::new("Fix selected"),
                        )
                        .clicked()
                    {
                        self.confirm = Some(ConfirmAction::Fix {
                            ids: self.selected.iter().cloned().collect(),
                        });
                    }
                    if let Some(backup) = last_backup.clone() {
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Button::new("Undo last fix"),
                            )
                            .clicked()
                        {
                            self.confirm = Some(ConfirmAction::Restore { backup });
                        }
                    }
                });
            });
            if let Some(error) = &error {
                ui.add(
                    egui::Label::new(
                        RichText::new(error).color(Color32::from_rgb(240, 100, 100)),
                    )
                    .wrap(),
                );
            } else {
                ui.add(egui::Label::new(RichText::new(status).weak()).wrap());
            }
            if let Some(stats) = &stats {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Ignored: {} allowlisted, {} excluded, {} inaccessible, {} with no verifiable path.",
                            stats.allowlisted,
                            stats.excluded,
                            stats.inaccessible,
                            stats.skipped
                        ))
                        .small()
                        .weak(),
                    )
                    .wrap(),
                );
            }
            if let Some((deleted, failed, backed_up, backup)) = last_fix_info {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Last fix: {deleted} removed, {failed} failed; {backed_up} entr(ies) in the backup."
                        ))
                        .small()
                        .weak(),
                    )
                    .wrap(),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("Backup file: {backup}")).small().weak(),
                    )
                    .wrap(),
                );
            }
            if let Some((restored, failed)) = last_restore_info {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Last restore: {restored} restored, {failed} failed."
                        ))
                        .small()
                        .weak(),
                    )
                    .wrap(),
                );
            }
            ui.add_space(2.0);
        });
    }

    fn central_panel(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(6.0);
            if !self.has_scanned {
                self.empty_state(ui);
                return;
            }
            if self.findings.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.heading(
                        RichText::new("No findings")
                            .color(Color32::from_rgb(110, 200, 130)),
                    );
                    ui.label(
                        "The registry has no broken references in the selected categories.",
                    );
                });
                return;
            }

            let query = self.search.trim().to_ascii_lowercase();
            let visible: Vec<Finding> = self
                .findings
                .iter()
                .filter(|finding| {
                    if query.is_empty() {
                        return true;
                    }
                    finding
                        .location()
                        .to_ascii_lowercase()
                        .contains(query.as_str())
                        || finding
                            .detail
                            .to_ascii_lowercase()
                            .contains(query.as_str())
                        || finding.category.slug().contains(query.as_str())
                })
                .cloned()
                .collect();

            ui.horizontal(|ui| {
                ui.heading("Findings");
                ui.label(
                    RichText::new(format!(
                        "{} visible of {}",
                        visible.len(),
                        self.findings.len()
                    ))
                    .weak(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Clear selection").clicked() {
                        self.selected.clear();
                    }
                    if ui.button("Select visible").clicked() {
                        for finding in &visible {
                            self.selected.insert(finding.id.clone());
                        }
                    }
                });
            });
            ui.separator();

            if visible.is_empty() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label("No items match the search.");
                });
                return;
            }

            let mut changes: Vec<(String, bool)> = Vec::new();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for finding in &visible {
                        let mut checked = self.selected.contains(&finding.id);
                        egui::Frame::group(ui.style())
                            .inner_margin(egui::Margin::same(8))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if ui.checkbox(&mut checked, "").changed() {
                                        changes.push((finding.id.clone(), checked));
                                    }
                                    risk_badge(ui, finding.risk);
                                    ui.label(
                                        RichText::new(finding.category.slug())
                                            .monospace()
                                            .weak(),
                                    );
                                    ui.label(
                                        RichText::new(&finding.id).monospace().weak(),
                                    );
                                });
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(finding.location()).monospace(),
                                    )
                                    .wrap(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&finding.detail).small().weak(),
                                    )
                                    .wrap(),
                                );
                            });
                        ui.add_space(4.0);
                    }
                });
            for (id, checked) in changes {
                if checked {
                    self.selected.insert(id);
                } else {
                    self.selected.remove(&id);
                }
            }
        });
    }

    fn empty_state(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(90.0);
            ui.heading("RegClean");
            ui.label(
                "Portable, read-only Windows Registry scanning with one reversible backup per cleanup.",
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Choose the categories and click Scan.").weak(),
            );
            if !self.admin {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Tip: run as administrator to fix keys under HKLM.",
                    )
                    .small()
                    .weak(),
                );
            }
        });
    }

    fn confirmation(&mut self, ctx: &egui::Context) {
        let Some(action) = self.confirm.clone() else {
            return;
        };
        let response = egui::Modal::new(egui::Id::unique("regclean_confirm")).show(ctx, |ui| {
            ui.set_width(540.0);
            match &action {
                ConfirmAction::Fix { ids } => {
                    ui.heading("Confirm fix");
                    ui.add_space(6.0);
                    ui.label(format!("{} entr(ies) will be fixed.", ids.len()));
                    ui.label(
                        "One .reg backup containing every selected entry is written before removal. If the backup fails, nothing is removed.",
                    );
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "Backup folder: {}",
                                backup::default_backup_root().display()
                            ))
                            .small()
                            .weak(),
                        )
                        .wrap(),
                    );
                    ui.add_space(8.0);
                    ui.colored_label(
                        Color32::from_rgb(235, 170, 70),
                        "Removing entries changes the registry. Review the selected items.",
                    );
                }
                ConfirmAction::Restore { backup } => {
                    ui.heading("Undo fix");
                    ui.add_space(6.0);
                    ui.label("The .reg backup will be imported back into the registry.");
                    ui.add(
                        egui::Label::new(
                            RichText::new(backup.display().to_string())
                                .monospace()
                                .small(),
                        )
                        .wrap(),
                    );
                    ui.add_space(8.0);
                    ui.colored_label(
                        Color32::from_rgb(235, 170, 70),
                        "Importing an old backup can overwrite newer values.",
                    );
                }
            }
            ui.add_space(12.0);
            let mut confirmed = false;
            let mut cancelled = false;
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    cancelled = true;
                }
                if ui
                    .add(egui::Button::new(RichText::new("Confirm").strong()))
                    .clicked()
                {
                    confirmed = true;
                }
            });
            (confirmed, cancelled)
        });
        let (confirmed, cancelled) = response.inner;
        if cancelled || response.should_close() {
            self.confirm = None;
            return;
        }
        if confirmed {
            self.confirm = None;
            match action {
                ConfirmAction::Fix { ids } => self.start_fix(ids),
                ConfirmAction::Restore { backup } => self.start_restore(backup),
            }
        }
    }
}

impl eframe::App for RegCleanApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.top_panel(ui);
        self.bottom_panel(ui);
        self.central_panel(ui);
        self.confirmation(ui.ctx());
        if self.busy {
            ui.ctx()
                .request_repaint_after(Duration::from_millis(100));
        }
    }
}

fn risk_badge(ui: &mut egui::Ui, risk: Risk) {
    let (label, color, help) = match risk {
        Risk::Low => (
            "LOW",
            Color32::from_rgb(110, 200, 130),
            "Low-impact removal: an isolated reference to a missing file.",
        ),
        Risk::Medium => (
            "MEDIUM",
            Color32::from_rgb(235, 170, 70),
            "Broader removal (whole key or COM server); review it first.",
        ),
        Risk::High => (
            "HIGH",
            Color32::from_rgb(240, 100, 100),
            "May affect an application that is still installed; review manually.",
        ),
    };
    ui.label(RichText::new(label).color(color).strong().monospace())
        .on_hover_text(help);
}
