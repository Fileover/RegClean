use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Uninstall,
    Startup,
    AppPaths,
    Applications,
    Com,
    ProgIds,
    HelpFiles,
    AppCompat,
    Installer,
    ShellExtensions,
    Services,
    Fonts,
    SharedDlls,
    MuiCache,
}

impl Category {
    pub const ALL: [Category; 14] = [
        Category::Uninstall,
        Category::Startup,
        Category::AppPaths,
        Category::Applications,
        Category::Com,
        Category::ProgIds,
        Category::HelpFiles,
        Category::AppCompat,
        Category::Installer,
        Category::ShellExtensions,
        Category::Services,
        Category::Fonts,
        Category::SharedDlls,
        Category::MuiCache,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Category::Uninstall => "uninstall",
            Category::Startup => "startup",
            Category::AppPaths => "app-paths",
            Category::Applications => "applications",
            Category::Com => "com",
            Category::ProgIds => "prog-ids",
            Category::HelpFiles => "help-files",
            Category::AppCompat => "app-compat",
            Category::Installer => "installer",
            Category::ShellExtensions => "shell-extensions",
            Category::Services => "services",
            Category::Fonts => "fonts",
            Category::SharedDlls => "shared-dlls",
            Category::MuiCache => "mui-cache",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Uninstall => "Orphaned installers",
            Category::Startup => "Startup",
            Category::AppPaths => "App Paths",
            Category::Applications => "Registered apps",
            Category::Com => "COM/ActiveX",
            Category::ProgIds => "Associations",
            Category::HelpFiles => "Help files",
            Category::AppCompat => "App compatibility",
            Category::Installer => "Installer folders",
            Category::ShellExtensions => "Shell extensions",
            Category::Services => "Services",
            Category::Fonts => "Fonts",
            Category::SharedDlls => "SharedDLLs",
            Category::MuiCache => "MuiCache",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Category::Uninstall => {
                "Programs and Features entries whose uninstaller points to a missing file."
            }
            Category::Startup => {
                "Run/RunOnce values whose referenced executable no longer exists."
            }
            Category::AppPaths => {
                "App Paths registrations whose default executable no longer exists."
            }
            Category::Applications => {
                "Applications shell\\<verb>\\Command entries whose executable no longer exists. When every existing command is broken, the target is the application key; if a working or unverifiable command exists, only the broken command is removed."
            }
            Category::Com => {
                "COM/ActiveX servers (InprocServer32/LocalServer32) that point to missing files, plus AppID and ProgID references that do not exist. The target is a server or reference subkey/value, never the whole CLSID."
            }
            Category::ProgIds => {
                "File extensions that point to a missing ProgID, or orphaned OpenWithProgids values."
            }
            Category::HelpFiles => {
                "Type library HELPDIR keys whose documentation path no longer exists."
            }
            Category::AppCompat => {
                "Compatibility Assistant cache entries whose executable no longer exists."
            }
            Category::Installer => {
                "Windows Installer folder registrations that point to missing directories."
            }
            Category::ShellExtensions => {
                "Approved shell extensions whose CLSID is no longer registered."
            }
            Category::Services => {
                "Service ImagePath values that point to a missing program. These are high risk and are not fixed by default."
            }
            Category::Fonts => {
                "Values under the Fonts key whose font file no longer exists."
            }
            Category::SharedDlls => {
                "Shared DLL counters whose file no longer exists."
            }
            Category::MuiCache => {
                "User MuiCache application paths that no longer exist."
            }
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    pub fn name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }

    pub fn regedit_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }

    pub fn key(self) -> RegKey {
        match self {
            Hive::LocalMachine => RegKey::predef(HKEY_LOCAL_MACHINE),
            Hive::CurrentUser => RegKey::predef(HKEY_CURRENT_USER),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub hive: Hive,
    /// Subkey path relative to the hive, without a leading slash.
    pub path: String,
    /// `Some(name)` removes only the value; `None` removes the whole key.
    pub value: Option<String>,
}

impl Target {
    pub fn key_location(&self) -> String {
        format!("{}\\{}", self.hive.name(), self.path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub risk: Risk,
    pub target: Target,
    pub detail: String,
}

impl Finding {
    pub fn new(category: Category, risk: Risk, target: Target, detail: String) -> Self {
        let mut finding = Finding {
            id: String::new(),
            category,
            risk,
            target,
            detail,
        };
        finding.id = fingerprint(category, &finding.target);
        finding
    }

    /// Human-readable location used for exclusions (`HKCU\...\Key::Value`).
    pub fn location(&self) -> String {
        match &self.target.value {
            Some(value) => {
                let value = if value.is_empty() { "(default)" } else { value };
                format!("{}::{}", self.target.key_location(), value)
            }
            None => self.target.key_location(),
        }
    }

}

fn fingerprint(category: Category, target: &Target) -> String {
    let material = format!(
        "{}|{}|{}|{}",
        category.slug(),
        target.hive.name(),
        target.path,
        target.value.as_deref().unwrap_or("<key>")
    );
    format!("{:08x}", fnv1a(&material) as u32)
}

fn fnv1a(input: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
