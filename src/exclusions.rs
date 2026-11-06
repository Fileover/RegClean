use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::paths;

/// Portable exclusions file: `<folder containing the exe>\regclean-exclusions.txt`.
pub fn path() -> PathBuf {
    paths::executable_dir().join("regclean-exclusions.txt")
}

pub fn read_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect())
}

pub fn load() -> Vec<String> {
    read_lines(&path()).unwrap_or_default()
}

/// Returns `true` when the prefix was actually added.
pub fn add(prefix: &str) -> Result<bool> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        bail!("the prefix cannot be empty");
    }
    let path = path();
    let entries = read_lines(&path)?;
    if entries
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(prefix))
    {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{prefix}")?;
    Ok(true)
}

/// Returns `true` when the prefix existed and was removed.
pub fn remove(prefix: &str) -> Result<bool> {
    let prefix = prefix.trim();
    let path = path();
    let entries = read_lines(&path)?;
    let before = entries.len();
    let retained: Vec<String> = entries
        .into_iter()
        .filter(|entry| !entry.eq_ignore_ascii_case(prefix))
        .collect();
    if retained.len() == before {
        return Ok(false);
    }
    let content = retained.join("\n");
    let content = if content.is_empty() {
        content
    } else {
        format!("{content}\n")
    };
    fs::write(&path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(true)
}
