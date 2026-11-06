use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use winreg::RegKey;

use crate::model::{Category, Finding, Hive, Risk, Target};
use crate::paths;
use crate::registry::{self, get_dword, get_string};

pub struct ScanOptions {
    pub categories: Vec<Category>,
    pub ignore_allowlist: bool,
    pub excludes: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub allowlisted: usize,
    pub inaccessible: usize,
    pub excluded: usize,
    pub skipped: usize,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
}

pub fn scan(options: &ScanOptions) -> ScanResult {
    let mut context = Context {
        options,
        stats: ScanStats::default(),
    };
    let mut findings = Vec::new();

    if context.wants(Category::Uninstall) {
        scan_uninstall(&mut context, &mut findings);
    }
    if context.wants(Category::Startup) {
        scan_startup(&mut context, &mut findings);
    }
    if context.wants(Category::AppPaths) {
        scan_app_paths(&mut context, &mut findings);
    }
    if context.wants(Category::Applications) {
        scan_applications(&mut context, &mut findings);
    }
    if context.wants(Category::Com) {
        scan_com(&mut context, &mut findings);
    }
    if context.wants(Category::ProgIds) {
        scan_progids(&mut context, &mut findings);
    }
    if context.wants(Category::HelpFiles) {
        scan_help_files(&mut context, &mut findings);
    }
    if context.wants(Category::AppCompat) {
        scan_app_compat(&mut context, &mut findings);
    }
    if context.wants(Category::Installer) {
        scan_installer_folders(&mut context, &mut findings);
    }
    if context.wants(Category::ShellExtensions) {
        scan_shell_extensions(&mut context, &mut findings);
    }
    if context.wants(Category::Services) {
        scan_services(&mut context, &mut findings);
    }
    if context.wants(Category::Fonts) {
        scan_fonts(&mut context, &mut findings);
    }
    if context.wants(Category::SharedDlls) {
        scan_shared_dlls(&mut context, &mut findings);
    }
    if context.wants(Category::MuiCache) {
        scan_mui_cache(&mut context, &mut findings);
    }

    findings.sort_by(|left, right| {
        category_rank(left.category)
            .cmp(&category_rank(right.category))
            .then_with(|| right.risk.cmp(&left.risk))
            .then_with(|| left.location().cmp(&right.location()))
    });
    let mut seen = HashSet::new();
    findings.retain(|finding| seen.insert(finding.id.clone()));

    ScanResult {
        findings,
        stats: context.stats,
    }
}

struct Context<'a> {
    options: &'a ScanOptions,
    stats: ScanStats,
}

enum Probe {
    Missing(PathBuf),
    Present,
    Skip,
}

impl Context<'_> {
    fn wants(&self, category: Category) -> bool {
        self.options.categories.is_empty() || self.options.categories.contains(&category)
    }

    fn note_error(&mut self, error: &io::Error) {
        if error.kind() != io::ErrorKind::NotFound {
            self.stats.inaccessible += 1;
        }
    }

    fn probe_command(&mut self, command: &str) -> Probe {
        match paths::extract_executable(command) {
            Some(executable) => self.probe_raw_path(&executable, true),
            None => {
                self.stats.skipped += 1;
                Probe::Skip
            }
        }
    }

    fn probe_raw_path(&mut self, raw: &str, honor_allowlist: bool) -> Probe {
        let Some(path) = paths::resolve_path(raw) else {
            self.stats.skipped += 1;
            return Probe::Skip;
        };
        self.probe_path(&path, honor_allowlist)
    }

    fn probe_path(&mut self, path: &Path, honor_allowlist: bool) -> Probe {
        if !paths::drive_available(path) {
            self.stats.skipped += 1;
            return Probe::Skip;
        }
        if honor_allowlist
            && !self.options.ignore_allowlist
            && paths::is_allowlisted(path)
        {
            self.stats.allowlisted += 1;
            return Probe::Skip;
        }
        if path.exists() {
            Probe::Present
        } else {
            Probe::Missing(path.to_path_buf())
        }
    }

    fn push(
        &mut self,
        findings: &mut Vec<Finding>,
        category: Category,
        risk: Risk,
        hive: Hive,
        key_path: String,
        value: Option<String>,
        detail: String,
    ) {
        let finding = Finding::new(
            category,
            risk,
            Target {
                hive,
                path: key_path,
                value,
            },
            detail,
        );
        if self.is_excluded(&finding.location()) {
            self.stats.excluded += 1;
            return;
        }
        findings.push(finding);
    }

    fn is_excluded(&self, location: &str) -> bool {
        let location = normalize(location);
        self.options.excludes.iter().any(|prefix| {
            let prefix = normalize(prefix);
            !prefix.is_empty() && location.starts_with(&prefix)
        })
    }
}

fn icon_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let candidate = raw
        .rsplit_once(',')
        .filter(|(_, index)| index.trim().parse::<i32>().is_ok())
        .map(|(path, _)| path)
        .unwrap_or(raw)
        .trim()
        .trim_matches('"')
        .trim();
    if candidate.is_empty() {
        return None;
    }
    paths::resolve_path(candidate).map(|_| candidate.to_string())
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn category_rank(category: Category) -> usize {
    Category::ALL
        .iter()
        .position(|candidate| *candidate == category)
        .unwrap_or(usize::MAX)
}

fn open_root(context: &mut Context, hive: Hive, path: &str) -> Option<RegKey> {
    match registry::open_read(hive, path) {
        Ok(key) => Some(key),
        Err(error) => {
            context.note_error(&error);
            None
        }
    }
}

const UNINSTALL_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
];

fn scan_uninstall(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in UNINSTALL_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for name in key.enum_keys().filter_map(Result::ok) {
            let subkey = match key.open_subkey(&name) {
                Ok(subkey) => subkey,
                Err(error) => {
                    context.note_error(&error);
                    continue;
                }
            };
            let has_values = subkey.enum_values().filter_map(Result::ok).next().is_some();
            let has_subkeys = subkey.enum_keys().filter_map(Result::ok).next().is_some();
            if !has_values && !has_subkeys {
                context.push(
                    findings,
                    Category::Uninstall,
                    Risk::Low,
                    *hive,
                    format!(r"{root}\{name}"),
                    None,
                    "empty uninstall entry (no values or subkeys)".to_string(),
                );
                continue;
            }
            let Some(display_name) = get_string(&subkey, "DisplayName") else {
                continue;
            };
            if get_dword(&subkey, "SystemComponent") == Some(1)
                || get_dword(&subkey, "NoRemove") == Some(1)
                || get_dword(&subkey, "WindowsInstaller") == Some(1)
                || registry::has_value(&subkey, "ParentKeyName")
            {
                continue;
            }
            if let Some(release_type) = get_string(&subkey, "ReleaseType") {
                let release_type = release_type.to_ascii_lowercase();
                if ["update", "hotfix", "servicepack", "security update"]
                    .iter()
                    .any(|marker| release_type.contains(marker))
                {
                    continue;
                }
            }

            if let Some(icon) = get_string(&subkey, "DisplayIcon")
                && let Some(icon) = icon_path(&icon)
                && let Probe::Missing(missing) = context.probe_raw_path(&icon, true)
            {
                context.push(
                    findings,
                    Category::Uninstall,
                    Risk::Low,
                    *hive,
                    format!(r"{root}\{name}"),
                    Some("DisplayIcon".to_string()),
                    format!(
                        "{display_name}: DisplayIcon points to a missing file: {}",
                        missing.display()
                    ),
                );
            }
            if let Some(source) = get_string(&subkey, "InstallSource")
                && let Probe::Missing(missing) = context.probe_raw_path(&source, true)
            {
                context.push(
                    findings,
                    Category::Uninstall,
                    Risk::Low,
                    *hive,
                    format!(r"{root}\{name}"),
                    Some("InstallSource".to_string()),
                    format!(
                        "{display_name}: InstallSource points to a missing folder: {}",
                        missing.display()
                    ),
                );
            }

            let Some(command) = ["UninstallString", "QuietUninstallString"]
                .iter()
                .find_map(|value_name| get_string(&subkey, value_name))
            else {
                continue;
            };
            let lower = command.to_ascii_lowercase();
            if lower.contains("msiexec") || lower.contains("msi.dll") {
                continue;
            }

            let Probe::Missing(missing) = context.probe_command(&command) else {
                continue;
            };
            let install_location_exists = get_string(&subkey, "InstallLocation")
                .and_then(|location| paths::resolve_path(&location))
                .is_some_and(|location| location.exists());

            let (risk, detail) = if install_location_exists {
                (
                    Risk::High,
                    format!(
                        "{display_name}: uninstaller missing ({}), but the install folder still exists; review manually",
                        missing.display()
                    ),
                )
            } else {
                (
                    Risk::Low,
                    format!(
                        "{display_name}: uninstaller does not exist: {}",
                        missing.display()
                    ),
                )
            };
            context.push(
                findings,
                Category::Uninstall,
                risk,
                *hive,
                format!(r"{root}\{name}"),
                None,
                detail,
            );
        }
    }
}

const RUN_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
];

fn scan_startup(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in RUN_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for (name, _) in key.enum_values().filter_map(Result::ok) {
            if name.is_empty() {
                continue;
            }
            let Some(command) = get_string(&key, &name) else {
                continue;
            };
            let Probe::Missing(missing) = context.probe_command(&command) else {
                continue;
            };
            context.push(
                findings,
                Category::Startup,
                Risk::Low,
                *hive,
                root.to_string(),
                Some(name),
                format!("startup executable does not exist: {}", missing.display()),
            );
        }
    }
}

const APP_PATHS_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\App Paths",
    ),
];

fn scan_app_paths(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in APP_PATHS_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for name in key.enum_keys().filter_map(Result::ok) {
            let subkey = match key.open_subkey(&name) {
                Ok(subkey) => subkey,
                Err(error) => {
                    context.note_error(&error);
                    continue;
                }
            };
            let Some(executable) = get_string(&subkey, "") else {
                continue;
            };
            let Probe::Missing(missing) = context.probe_command(&executable) else {
                continue;
            };
            context.push(
                findings,
                Category::AppPaths,
                Risk::Low,
                *hive,
                format!(r"{root}\{name}"),
                None,
                format!(
                    "App Path '{name}' points to a missing executable: {}",
                    missing.display()
                ),
            );
        }
    }
}

const APPLICATION_ROOTS: &[(Hive, &str)] = &[
    (Hive::LocalMachine, r"SOFTWARE\Classes\Applications"),
    (
        Hive::LocalMachine,
        r"SOFTWARE\Classes\WOW6432Node\Applications",
    ),
    (Hive::CurrentUser, r"Software\Classes\Applications"),
    (
        Hive::CurrentUser,
        r"Software\Classes\WOW6432Node\Applications",
    ),
];

fn scan_applications(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in APPLICATION_ROOTS {
        let Some(applications) = open_root(context, *hive, root) else {
            continue;
        };
        for application in applications.enum_keys().filter_map(Result::ok) {
            let Ok(application_key) = applications.open_subkey(&application) else {
                continue;
            };
            let Ok(shell) = application_key.open_subkey("shell") else {
                continue;
            };
            let mut broken: Vec<(String, PathBuf)> = Vec::new();
            let mut working = 0usize;
            let mut unverifiable = false;
            for verb in shell.enum_keys().filter_map(Result::ok) {
                let Ok(verb_key) = shell.open_subkey(&verb) else {
                    continue;
                };
                let Ok(command_key) = verb_key.open_subkey("command") else {
                    continue;
                };
                let Some(command) = get_string(&command_key, "") else {
                    continue;
                };
                match context.probe_command(&command) {
                    Probe::Missing(path) => broken.push((verb, path)),
                    Probe::Present => working += 1,
                    Probe::Skip => unverifiable = true,
                }
            }
            if broken.is_empty() {
                continue;
            }

            // Remove the whole key only when it is safe to say that no working
            // command and no unverifiable command remains.
            if working == 0 && !unverifiable {
                let verbs = broken
                    .iter()
                    .map(|(verb, _)| verb.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let details = broken
                    .iter()
                    .map(|(verb, path)| format!("{verb} -> {}", path.display()))
                    .collect::<Vec<_>>()
                    .join("; ");
                context.push(
                    findings,
                    Category::Applications,
                    Risk::Medium,
                    *hive,
                    format!(r"{root}\{application}"),
                    None,
                    format!(
                        "{application}: all existing commands ({verbs}) point to missing executables; the target is the application key. {details}"
                    ),
                );
            } else {
                for (verb, missing) in broken {
                    context.push(
                        findings,
                        Category::Applications,
                        Risk::Low,
                        *hive,
                        format!(r"{root}\{application}\shell\{verb}\command"),
                        Some(String::new()),
                        format!(
                            "{application}: the '{verb}' command points to a missing executable: {}",
                            missing.display()
                        ),
                    );
                }
            }
        }
    }
}

const COM_ROOTS: &[(Hive, &str)] = &[
    (Hive::LocalMachine, r"SOFTWARE\Classes\CLSID"),
    (Hive::LocalMachine, r"SOFTWARE\Classes\WOW6432Node\CLSID"),
    (Hive::CurrentUser, r"Software\Classes\CLSID"),
    (Hive::CurrentUser, r"Software\Classes\WOW6432Node\CLSID"),
];

const COM_SERVERS: &[&str] = &["InprocServer32", "LocalServer32", "InprocHandler32"];

fn scan_com(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in COM_ROOTS {
        let Some(clsid_root) = open_root(context, *hive, root) else {
            continue;
        };
        for clsid in clsid_root.enum_keys().filter_map(Result::ok) {
            if !clsid.starts_with('{') {
                continue;
            }
            let Ok(clsid_key) = clsid_root.open_subkey(&clsid) else {
                continue;
            };
            for server in COM_SERVERS {
                let Ok(server_key) = clsid_key.open_subkey(server) else {
                    continue;
                };
                let Some(command) = get_string(&server_key, "") else {
                    continue;
                };
                let Probe::Missing(missing) = context.probe_command(&command) else {
                    continue;
                };
                context.push(
                    findings,
                    Category::Com,
                    Risk::Medium,
                    *hive,
                    format!(r"{root}\{clsid}\{server}"),
                    None,
                    format!(
                        "CLSID {clsid}: {server} points to a missing file: {}",
                        missing.display()
                    ),
                );
            }

            if let Some(appid) = get_string(&clsid_key, "AppID") {
                let appid = appid.trim();
                if appid.starts_with('{') && appid.ends_with('}') && !appid_exists(appid) {
                    context.push(
                        findings,
                        Category::Com,
                        Risk::Low,
                        *hive,
                        format!(r"{root}\{clsid}"),
                        Some("AppID".to_string()),
                        format!("CLSID {clsid}: AppID {appid} is not registered"),
                    );
                }
            }

            for reference in ["ProgID", "VersionIndependentProgID"] {
                let Ok(reference_key) = clsid_key.open_subkey(reference) else {
                    continue;
                };
                let Some(progid) = get_string(&reference_key, "") else {
                    continue;
                };
                let progid = progid.trim();
                if progid.is_empty() || progid_exists(progid) {
                    continue;
                }
                context.push(
                    findings,
                    Category::Com,
                    Risk::Low,
                    *hive,
                    format!(r"{root}\{clsid}\{reference}"),
                    None,
                    format!("CLSID {clsid}: {reference} references missing ProgID {progid}"),
                );
            }
        }
    }
}

const CLASSES_ROOTS: &[(Hive, &str)] =
    &[(Hive::LocalMachine, r"SOFTWARE\Classes"), (Hive::CurrentUser, r"Software\Classes")];

fn scan_progids(context: &mut Context, findings: &mut Vec<Finding>) {
    let mut cache: HashMap<String, bool> = HashMap::new();

    for (hive, root) in CLASSES_ROOTS {
        let Some(classes) = open_root(context, *hive, root) else {
            continue;
        };
        for extension in classes.enum_keys().filter_map(Result::ok) {
            if !extension.starts_with('.') || extension.len() < 2 {
                continue;
            }
            let Ok(extension_key) = classes.open_subkey(&extension) else {
                continue;
            };

            if let Some(progid) = get_string(&extension_key, "") {
                let exists = *cache
                    .entry(progid.clone())
                    .or_insert_with(|| progid_exists(&progid));
                if !exists {
                    context.push(
                        findings,
                        Category::ProgIds,
                        Risk::Low,
                        *hive,
                        format!(r"{root}\{extension}"),
                        Some(String::new()),
                        format!("extension {extension} points to a missing ProgID: {progid}"),
                    );
                }
            }

            let Ok(open_with) = extension_key.open_subkey("OpenWithProgids") else {
                continue;
            };
            for (progid, _) in open_with.enum_values().filter_map(Result::ok) {
                if progid.is_empty() {
                    continue;
                }
                let exists = *cache
                    .entry(progid.clone())
                    .or_insert_with(|| progid_exists(&progid));
                if !exists {
                    context.push(
                        findings,
                        Category::ProgIds,
                        Risk::Low,
                        *hive,
                        format!(r"{root}\{extension}\OpenWithProgids"),
                        Some(progid.clone()),
                        format!("OpenWithProgids for {extension} points to a missing ProgID: {progid}"),
                    );
                }
            }
        }
    }
}

fn progid_exists(progid: &str) -> bool {
    let progid = progid.trim();
    if progid.is_empty() {
        return true;
    }
    let direct = [
        (Hive::LocalMachine, format!(r"SOFTWARE\Classes\{progid}")),
        (
            Hive::LocalMachine,
            format!(r"SOFTWARE\Classes\WOW6432Node\{progid}"),
        ),
        (Hive::CurrentUser, format!(r"Software\Classes\{progid}")),
        (
            Hive::CurrentUser,
            format!(r"Software\Classes\WOW6432Node\{progid}"),
        ),
    ];
    if direct
        .iter()
        .any(|(hive, path)| registry::key_exists(*hive, path))
    {
        return true;
    }
    if progid.starts_with('{') && progid.ends_with('}') {
        let as_clsid = [
            (Hive::LocalMachine, format!(r"SOFTWARE\Classes\CLSID\{progid}")),
            (
                Hive::LocalMachine,
                format!(r"SOFTWARE\Classes\WOW6432Node\CLSID\{progid}"),
            ),
            (Hive::CurrentUser, format!(r"Software\Classes\CLSID\{progid}")),
        ];
        return as_clsid
            .iter()
            .any(|(hive, path)| registry::key_exists(*hive, path));
    }
    false
}

const FONT_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows NT\CurrentVersion\Fonts",
    ),
];

fn scan_fonts(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in FONT_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for (name, _) in key.enum_values().filter_map(Result::ok) {
            let Some(file_name) = get_string(&key, &name) else {
                continue;
            };
            if file_name.starts_with('@') {
                continue;
            }
            let candidates = font_candidates(*hive, &file_name);
            if candidates.is_empty() {
                context.stats.skipped += 1;
                continue;
            }
            let mut missing = None;
            let mut found = false;
            for candidate in &candidates {
                if !paths::drive_available(candidate) {
                    continue;
                }
                if candidate.exists() {
                    found = true;
                    break;
                }
                if missing.is_none() {
                    missing = Some(candidate.clone());
                }
            }
            if found {
                continue;
            }
            let Some(missing) = missing else {
                context.stats.skipped += 1;
                continue;
            };
            context.push(
                findings,
                Category::Fonts,
                Risk::Low,
                *hive,
                root.to_string(),
                Some(name),
                format!("missing font file: {}", missing.display()),
            );
        }
    }
}

fn font_candidates(hive: Hive, file_name: &str) -> Vec<PathBuf> {
    if file_name.contains(':') || file_name.starts_with('\\') {
        return paths::resolve_path(file_name).into_iter().collect();
    }
    let mut candidates = Vec::new();
    if hive == Hive::CurrentUser
        && let Some(local_app_data) = std::env::var_os("LOCALAPPDATA")
    {
        candidates.push(
            PathBuf::from(local_app_data)
                .join(r"Microsoft\Windows\Fonts")
                .join(file_name),
        );
    }
    candidates.push(paths::windir().join("Fonts").join(file_name));
    candidates
}

const SHARED_DLLS_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs",
    ),
];

fn scan_shared_dlls(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in SHARED_DLLS_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for (name, _) in key.enum_values().filter_map(Result::ok) {
            if name.is_empty() {
                continue;
            }
            let Probe::Missing(missing) = context.probe_raw_path(&name, true) else {
                continue;
            };
            context.push(
                findings,
                Category::SharedDlls,
                Risk::Low,
                *hive,
                root.to_string(),
                Some(name),
                format!(
                    "registered shared DLL does not exist: {}",
                    missing.display()
                ),
            );
        }
    }
}

const MUI_ROOTS: &[(Hive, &str)] = &[(
    Hive::CurrentUser,
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
)];

fn scan_mui_cache(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in MUI_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for (name, _) in key.enum_values().filter_map(Result::ok) {
            let lower = name.to_ascii_lowercase();
            let suffix_len = if lower.ends_with(".friendlyappname") {
                ".friendlyappname".len()
            } else if lower.ends_with(".applicationcompany") {
                ".applicationcompany".len()
            } else {
                continue;
            };
            let executable = name[..name.len() - suffix_len].trim();
            if executable.is_empty() {
                continue;
            }
            let Probe::Missing(missing) = context.probe_command(executable) else {
                continue;
            };
            context.push(
                findings,
                Category::MuiCache,
                Risk::Low,
                *hive,
                root.to_string(),
                Some(name),
                format!("MuiCache path does not exist: {}", missing.display()),
            );
        }
    }
}

fn clsid_exists(clsid: &str) -> bool {
    [
        (
            Hive::LocalMachine,
            format!(r"SOFTWARE\Classes\CLSID\{clsid}"),
        ),
        (
            Hive::LocalMachine,
            format!(r"SOFTWARE\Classes\WOW6432Node\CLSID\{clsid}"),
        ),
        (Hive::CurrentUser, format!(r"Software\Classes\CLSID\{clsid}")),
        (
            Hive::CurrentUser,
            format!(r"Software\Classes\WOW6432Node\CLSID\{clsid}"),
        ),
    ]
    .iter()
    .any(|(hive, path)| registry::key_exists(*hive, path))
}

fn appid_exists(appid: &str) -> bool {
    [
        (
            Hive::LocalMachine,
            format!(r"SOFTWARE\Classes\AppID\{appid}"),
        ),
        (
            Hive::LocalMachine,
            format!(r"SOFTWARE\Classes\WOW6432Node\AppID\{appid}"),
        ),
        (Hive::CurrentUser, format!(r"Software\Classes\AppID\{appid}")),
        (
            Hive::CurrentUser,
            format!(r"Software\Classes\WOW6432Node\AppID\{appid}"),
        ),
    ]
    .iter()
    .any(|(hive, path)| registry::key_exists(*hive, path))
}

const HELP_ROOTS: &[(Hive, &str)] = &[
    (Hive::LocalMachine, r"SOFTWARE\Classes\TypeLib"),
    (
        Hive::LocalMachine,
        r"SOFTWARE\Classes\WOW6432Node\TypeLib",
    ),
    (Hive::CurrentUser, r"Software\Classes\TypeLib"),
];

fn scan_help_files(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in HELP_ROOTS {
        let Some(type_libs) = open_root(context, *hive, root) else {
            continue;
        };
        for type_lib in type_libs.enum_keys().filter_map(Result::ok) {
            let Ok(type_lib_key) = type_libs.open_subkey(&type_lib) else {
                continue;
            };
            for version in type_lib_key.enum_keys().filter_map(Result::ok) {
                let Ok(version_key) = type_lib_key.open_subkey(&version) else {
                    continue;
                };
                let Ok(help_key) = version_key.open_subkey("HELPDIR") else {
                    continue;
                };
                let Some(folder) = get_string(&help_key, "") else {
                    continue;
                };
                let Probe::Missing(missing) = context.probe_raw_path(&folder, false) else {
                    continue;
                };
                context.push(
                    findings,
                    Category::HelpFiles,
                    Risk::Low,
                    *hive,
                    format!(r"{root}\{type_lib}\{version}\HELPDIR"),
                    None,
                    format!("help path does not exist: {}", missing.display()),
                );
            }
        }
    }
}

fn scan_app_compat(context: &mut Context, findings: &mut Vec<Finding>) {
    let root = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";
    let Some(key) = open_root(context, Hive::CurrentUser, root) else {
        return;
    };
    for (name, _) in key.enum_values().filter_map(Result::ok) {
        if name.trim().is_empty() {
            continue;
        }
        let Probe::Missing(missing) = context.probe_raw_path(&name, false) else {
            continue;
        };
        context.push(
            findings,
            Category::AppCompat,
            Risk::Low,
            Hive::CurrentUser,
            root.to_string(),
            Some(name),
            format!(
                "Compatibility Assistant cache references a missing executable: {}",
                missing.display()
            ),
        );
    }
}

const INSTALLER_FOLDER_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
    ),
    (
        Hive::LocalMachine,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\Folders",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Installer\Folders",
    ),
];

fn scan_installer_folders(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in INSTALLER_FOLDER_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for (name, _) in key.enum_values().filter_map(Result::ok) {
            if name.trim().is_empty() {
                continue;
            }
            let Probe::Missing(missing) = context.probe_raw_path(&name, false) else {
                continue;
            };
            context.push(
                findings,
                Category::Installer,
                Risk::Low,
                *hive,
                root.to_string(),
                Some(name),
                format!("installer folder does not exist: {}", missing.display()),
            );
        }
    }
}

const APPROVED_SHELL_ROOTS: &[(Hive, &str)] = &[
    (
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    ),
    (
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    ),
];

fn scan_shell_extensions(context: &mut Context, findings: &mut Vec<Finding>) {
    for (hive, root) in APPROVED_SHELL_ROOTS {
        let Some(key) = open_root(context, *hive, root) else {
            continue;
        };
        for (name, _) in key.enum_values().filter_map(Result::ok) {
            if !name.starts_with('{') || !name.ends_with('}') || clsid_exists(&name) {
                continue;
            }
            let label = get_string(&key, &name).unwrap_or_default();
            context.push(
                findings,
                Category::ShellExtensions,
                Risk::Low,
                *hive,
                root.to_string(),
                Some(name.clone()),
                format!("approved shell extension '{label}' uses unregistered CLSID {name}"),
            );
        }
    }
}

fn scan_services(context: &mut Context, findings: &mut Vec<Finding>) {
    let root = r"SYSTEM\CurrentControlSet\Services";
    let Some(services) = open_root(context, Hive::LocalMachine, root) else {
        return;
    };
    for service in services.enum_keys().filter_map(Result::ok) {
        let Ok(service_key) = services.open_subkey(&service) else {
            continue;
        };
        let Some(image_path) = get_string(&service_key, "ImagePath") else {
            continue;
        };
        let Some(executable) = paths::extract_executable(&image_path) else {
            continue;
        };
        let Probe::Missing(missing) = context.probe_raw_path(&executable, false) else {
            continue;
        };
        context.push(
            findings,
            Category::Services,
            Risk::High,
            Hive::LocalMachine,
            format!(r"{root}\{service}"),
            Some("ImagePath".to_string()),
            format!(
                "service program does not exist: {}; review before removing",
                missing.display()
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::icon_path;

    #[test]
    fn icon_path_keeps_unquoted_spaces_and_drops_index() {
        assert_eq!(
            icon_path(r"C:\Program Files\App\app.exe,0"),
            Some(r"C:\Program Files\App\app.exe".to_string())
        );
    }

    #[test]
    fn icon_path_keeps_quoted_path() {
        assert_eq!(
            icon_path(r#""C:\Program Files\App\app.exe",-1"#),
            Some(r"C:\Program Files\App\app.exe".to_string())
        );
    }
}
