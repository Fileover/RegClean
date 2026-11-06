use std::fs;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};

use chrono::Local;
use serde::Serialize;
use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::{
    KEY_READ, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_SZ,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::model::Finding;
use crate::paths;
use crate::registry;

pub const TOOL_NAME: &str = "regclean";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize)]
pub struct RestoreSummary {
    pub restored: usize,
    pub failed: usize,
    pub cancelled: bool,
}

/// Portable backup root: `<folder containing the exe>\backup`.
pub fn default_backup_root() -> PathBuf {
    paths::executable_dir().join("backup")
}

pub fn backup_root(custom_root: Option<&Path>) -> PathBuf {
    custom_root
        .map(Path::to_path_buf)
        .unwrap_or_else(default_backup_root)
}

/// Create the portable backup folder and return the single .reg file for this run.
pub fn new_backup_file(custom_root: Option<&Path>) -> Result<PathBuf, String> {
    let root = backup_root(custom_root);
    fs::create_dir_all(&root)
        .map_err(|error| format!("could not create backup folder {}: {error}", root.display()))?;

    let stamp = Local::now().format("%Y%m%d-%H%M%S");
    let mut candidate = root.join(format!("regclean-{stamp}.reg"));
    let mut suffix = 2;
    while candidate.exists() {
        candidate = root.join(format!("regclean-{stamp}-{suffix}.reg"));
        suffix += 1;
    }
    Ok(candidate)
}

/// Export all selected findings into one .reg file. The whole body is built in
/// memory first, so a read failure never leaves a partial backup behind.
pub fn export_findings(findings: &[Finding], destination: &Path) -> Result<(), String> {
    if findings.is_empty() {
        return Err("no findings to back up".to_string());
    }

    let mut body = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    for finding in findings {
        let root = registry::open_read(finding.target.hive, &finding.target.path).map_err(
            |error| {
                format!(
                    "could not open {}: {}",
                    finding.target.key_location(),
                    registry::friendly(&error)
                )
            },
        )?;
        let full_path = format!(
            "{}\\{}",
            registry::hive_regedit_name(finding.target.hive),
            finding.target.path
        );

        match &finding.target.value {
            Some(value) => write_section(&mut body, &full_path, &root, Some(value))?,
            None => write_tree(&mut body, &full_path, &root)?,
        }
    }

    if let Err(error) = write_reg_file(destination, &body) {
        let _ = fs::remove_file(destination);
        return Err(format!(
            "failed to write backup {}: {error}",
            destination.display()
        ));
    }
    Ok(())
}

fn write_tree(body: &mut String, full_path: &str, key: &RegKey) -> Result<(), String> {
    write_section(body, full_path, key, None)?;
    let mut subkeys: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();
    subkeys.sort();
    for subkey in subkeys {
        let child = key.open_subkey_with_flags(&subkey, KEY_READ).map_err(|error| {
            format!(
                "key {full_path}\\{subkey} is inaccessible for backup: {}",
                registry::friendly(&error)
            )
        })?;
        write_tree(body, &format!("{full_path}\\{subkey}"), &child)?;
    }
    Ok(())
}

fn write_section(
    body: &mut String,
    full_path: &str,
    key: &RegKey,
    only_value: Option<&str>,
) -> Result<(), String> {
    body.push('[');
    body.push_str(full_path);
    body.push_str("]\r\n");

    match only_value {
        Some(value) => {
            let raw = key
                .get_raw_value(value)
                .map_err(|error| format!("value '{value}' is unreadable: {error}"))?;
            write_raw_value(body, value, &raw);
        }
        None => {
            let mut values: Vec<(String, RegValue<'static>)> = key
                .enum_values()
                .filter_map(Result::ok)
                .collect();
            values.sort_by(|left, right| left.0.cmp(&right.0));
            for (name, _) in values {
                let raw = key
                    .get_raw_value(&name)
                    .map_err(|error| format!("value '{name}' is unreadable: {error}"))?;
                write_raw_value(body, &name, &raw);
            }
        }
    }

    body.push_str("\r\n");
    Ok(())
}

fn write_raw_value(body: &mut String, name: &str, raw: &RegValue<'_>) {
    let display_name = if name.is_empty() {
        "@".to_string()
    } else {
        quote_string(name)
    };

    match raw.vtype.clone() {
        REG_SZ => {
            let decoded = decode_utf16(&raw.bytes);
            if decoded
                .chars()
                .any(|character| character.is_control() && character != '\t')
            {
                write_hex(body, &display_name, "hex(1)", &raw.bytes);
            } else {
                body.push_str(&display_name);
                body.push('=');
                body.push_str(&quote_string(&decoded));
                body.push_str("\r\n");
            }
        }
        REG_EXPAND_SZ => {
            // hex(2) preserves the expandable string type on import.
            write_hex(body, &display_name, "hex(2)", &raw.bytes);
        }
        REG_DWORD if raw.bytes.len() == 4 => {
            let value = u32::from_le_bytes([
                raw.bytes[0],
                raw.bytes[1],
                raw.bytes[2],
                raw.bytes[3],
            ]);
            body.push_str(&format!("{display_name}=dword:{value:08x}\r\n"));
        }
        REG_QWORD if raw.bytes.len() == 8 => {
            write_hex(body, &display_name, "hex(b)", &raw.bytes);
        }
        REG_MULTI_SZ => {
            write_hex(body, &display_name, "hex(7)", &raw.bytes);
        }
        REG_BINARY => {
            write_hex(body, &display_name, "hex", &raw.bytes);
        }
        REG_NONE => {
            write_hex(body, &display_name, "hex(0)", &raw.bytes);
        }
        other => {
            write_hex(
                body,
                &display_name,
                &format!("hex({})", other as u32),
                &raw.bytes,
            );
        }
    }
}

fn write_hex(body: &mut String, display_name: &str, prefix: &str, bytes: &[u8]) {
    body.push_str(display_name);
    body.push('=');
    body.push_str(prefix);
    body.push(':');
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            body.push(',');
            if index % 25 == 0 {
                body.push_str("\\\r\n  ");
            }
        }
        body.push_str(&format!("{byte:02x}"));
    }
    body.push_str("\r\n");
}

fn write_reg_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut data = Vec::with_capacity(content.len() * 2 + 2);
    data.extend_from_slice(&[0xff, 0xfe]);
    for unit in content.encode_utf16() {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    file.write_all(&data)
}

fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    text.trim_end_matches('\0').to_string()
}

fn quote_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            _ => output.push(character),
        }
    }
    output.push('"');
    output
}

pub fn import_reg_file(path: &Path) -> Result<(), String> {
    let output = std::process::Command::new("reg.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("import")
        .arg(path)
        .output()
        .map_err(|error| format!("could not run reg.exe: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "reg import failed ({}): {} {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_reg_strings() {
        assert_eq!(quote_string(r#"C:\Apps\a"b.exe"#), r#""C:\\Apps\\a\"b.exe""#);
    }

    #[test]
    fn decodes_utf16_with_trailing_nul() {
        let mut bytes = Vec::new();
        for unit in "test\0".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_utf16(&bytes), "test");
    }

    #[test]
    fn hex_wraps_lines() {
        let mut body = String::new();
        write_hex(&mut body, "\"x\"", "hex", &[0u8; 60]);
        assert!(body.contains("\\\r\n  "));
        assert!(body.ends_with("\r\n"));
    }

    #[test]
    fn backup_root_is_portable() {
        assert_eq!(
            default_backup_root().file_name().and_then(|name| name.to_str()),
            Some("backup")
        );
    }
}
