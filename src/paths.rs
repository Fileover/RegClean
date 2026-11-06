use std::path::{Path, PathBuf};

use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;

/// Expands `%VAR%` with the Windows API (unknown variables are left unchanged).
pub fn expand_env(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    unsafe {
        let wide: Vec<u16> = input.encode_utf16().chain(std::iter::once(0)).collect();
        let needed = ExpandEnvironmentStringsW(wide.as_ptr(), std::ptr::null_mut(), 0);
        if needed == 0 {
            return input.to_string();
        }
        let mut buffer = vec![0u16; needed as usize];
        let written = ExpandEnvironmentStringsW(wide.as_ptr(), buffer.as_mut_ptr(), needed);
        if written == 0 {
            return input.to_string();
        }
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
    }
}

pub fn windir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// Folder containing the running executable. Portable data lives here.
pub fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `KnownFolder` GUIDs that appear as registry path prefixes
/// (for example in MuiCache and Run), mapped to their equivalent folders.
fn known_folder(guid: &str) -> Option<String> {
    let value = match guid.to_ascii_uppercase().as_str() {
        "{6D809377-6AF0-444B-8957-A3773F02200E}" => std::env::var("ProgramFiles").ok(),
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}" => std::env::var("ProgramFiles(x86)").ok(),
        "{F38BF404-1D43-42F2-9305-67DE0B28FC23}" => {
            Some(format!(r"{}\SysWOW64", windir().display()))
        }
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}" => {
            Some(format!(r"{}\System32", windir().display()))
        }
        "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}" => std::env::var("LOCALAPPDATA").ok(),
        "{5E6C858F-0E22-4760-9AFE-EA3317B67173}" => std::env::var("USERPROFILE").ok(),
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}" => std::env::var("APPDATA")
            .ok()
            .map(|base| format!(r"{base}\Microsoft\Windows\Start Menu\Programs")),
        _ => None,
    }?;
    Some(value)
}

fn expand_known_folder_prefix(input: &str) -> String {
    if !input.starts_with('{') {
        return input.to_string();
    }
    let Some(end) = input.find('}') else {
        return input.to_string();
    };
    let Some(base) = known_folder(&input[..=end]) else {
        return input.to_string();
    };
    let rest = input[end + 1..].trim_start_matches(['\\', '/']);
    if rest.is_empty() {
        base
    } else {
        format!(r"{}\{}", base.trim_end_matches(['\\', '/']), rest)
    }
}

/// Converts a registry string into a local absolute path, or `None` when there
/// is not enough evidence to check it (URL, UNC, relative path, or an
/// unexpanded variable).
pub fn resolve_path(raw: &str) -> Option<PathBuf> {
    let expanded = expand_env(raw.trim());
    let expanded = expand_known_folder_prefix(expanded.trim());
    let mut candidate = expanded.trim().trim_matches('"').trim();
    if let Some(stripped) = candidate.strip_prefix(r"\??\") {
        candidate = stripped;
    }
    if candidate.is_empty()
        || candidate.starts_with('%')
        || candidate.starts_with("\\\\")
        || candidate.contains("://")
        || candidate.starts_with('-')
    {
        return None;
    }
    let path = Path::new(candidate);
    if !path.is_absolute() {
        return None;
    }
    Some(path.to_path_buf())
}

fn looks_absolute(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    (bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/'))
        || raw.starts_with("\\\\")
}

fn file_name_lower(raw: &str) -> String {
    Path::new(raw)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Extracts the executable (or a launcher's DLL) from a registry command line.
pub fn extract_executable(command: &str) -> Option<String> {
    let expanded = expand_env(command.trim());
    let command = expanded.trim();
    if command.is_empty() {
        return None;
    }

    if let Some(stripped) = command.strip_prefix('"') {
        let end = stripped.find('"')?;
        let exe = &stripped[..end];
        if exe.is_empty() {
            return None;
        }
        if is_launcher_with_target(exe) {
            return launcher_argument(&stripped[end + 1..]).or_else(|| Some(exe.to_string()));
        }
        return Some(exe.to_string());
    }

    let lower = command.to_ascii_lowercase();
    for extension in [
        ".exe", ".com", ".bat", ".cmd", ".dll", ".scr", ".cpl", ".msi", ".sys",
    ] {
        if let Some(position) = lower.find(extension) {
            let end = position + extension.len();
            let next = command[end..].chars().next();
            let boundary = next.is_none_or(|ch| ch.is_whitespace() || ch == ',' || ch == '"');
            if boundary {
                let exe = &command[..end];
                if is_launcher_with_target(exe) {
                    return launcher_argument(&command[end..]).or_else(|| Some(exe.to_string()));
                }
                return Some(exe.to_string());
            }
        }
    }

    command
        .split_whitespace()
        .next()
        .map(ToString::to_string)
}

fn is_launcher_with_target(exe: &str) -> bool {
    matches!(
        file_name_lower(exe).as_str(),
        "rundll32.exe" | "regsvr32.exe" | "mshta.exe"
    )
}

fn launcher_argument(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    let argument = if let Some(stripped) = rest.strip_prefix('"') {
        &stripped[..stripped.find('"')?]
    } else {
        rest.split([',', ' ', '\t']).next()?
    };
    if looks_absolute(argument) {
        Some(argument.to_string())
    } else {
        None
    }
}

/// System paths, installer caches, and vendor folders that should never become
/// cleanup suggestions, even when the file is missing.
pub fn is_allowlisted(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let system_root = windir()
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    if normalized == system_root || normalized.starts_with(&format!("{system_root}\\")) {
        return true;
    }

    const PROTECTED_MARKERS: &[&str] = &[
        "\\winsxs\\",
        "\\windowsapps\\",
        "\\package cache\\",
        "\\installer\\",
        "\\driverstore\\",
        "\\drivers\\",
        "\\servicing\\",
        "\\assembly\\",
        "\\common files\\",
        "\\system32\\",
        "\\syswow64\\",
    ];
    if PROTECTED_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return true;
    }

    const VENDOR_MARKERS: &[&str] = &[
        "microsoft",
        "intel",
        "nvidia",
        "advanced micro devices",
        "realtek",
        "synaptics",
        "qualcomm",
        "broadcom",
        "asus",
        "micro-star",
        "msi",
        "dell",
        "lenovo",
        "hewlett-packard",
        "acer",
        "toshiba",
        "samsung",
        "logitech",
        "corsair",
        "razer",
        "gigabyte",
        "asrock",
    ];
    normalized
        .split('\\')
        .any(|segment| VENDOR_MARKERS.iter().any(|vendor| segment.contains(vendor)))
}

/// Do not flag a path on a removed/disconnected drive: this is a classic
/// cleaner false positive (USB drive, external disk, network drive).
pub fn drive_available(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/') {
        return Path::new(&text[..3]).exists();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_quoted_executable_with_arguments() {
        assert_eq!(
            extract_executable(r#""C:\Program Files\App\app.exe" --background"#),
            Some(r"C:\Program Files\App\app.exe".to_string())
        );
    }

    #[test]
    fn extracts_unquoted_executable_with_spaces() {
        assert_eq!(
            extract_executable(r"C:\Program Files\App\app.exe /silent"),
            Some(r"C:\Program Files\App\app.exe".to_string())
        );
    }

    #[test]
    fn extracts_rundll32_dll() {
        assert_eq!(
            extract_executable(r"C:\Windows\System32\rundll32.exe C:\Apps\Foo\hook.dll,Entry"),
            Some(r"C:\Apps\Foo\hook.dll".to_string())
        );
    }

    #[test]
    fn ignores_msiexec() {
        assert_eq!(
            extract_executable(r"MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"),
            Some("MsiExec.exe".to_string())
        );
        assert!(resolve_path("MsiExec.exe").is_none());
    }

    #[test]
    fn rejects_unc_and_relative_paths() {
        assert!(resolve_path(r"\\servidor\share\app.exe").is_none());
        assert!(resolve_path(r"app.exe").is_none());
        assert!(resolve_path(r"%NAO_EXISTE%\app.exe").is_none());
    }

    #[test]
    fn allowlist_blocks_system_and_vendor_paths() {
        assert!(is_allowlisted(Path::new(r"C:\Windows\System32\foo.dll")));
        assert!(is_allowlisted(Path::new(
            r"C:\Program Files\NVIDIA Corporation\foo.exe"
        )));
        assert!(!is_allowlisted(Path::new(r"C:\Apps\Loja\foo.exe")));
    }
}
