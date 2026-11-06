use std::io;

use winreg::RegKey;
use winreg::enums::{DELETE, KEY_READ, KEY_WRITE};

use crate::model::Hive;

const KEY_DELETE: u32 = KEY_READ | KEY_WRITE | DELETE;

pub fn open(hive: Hive, path: &str, flags: u32) -> io::Result<RegKey> {
    hive.key().open_subkey_with_flags(path, flags)
}

pub fn open_read(hive: Hive, path: &str) -> io::Result<RegKey> {
    open(hive, path, KEY_READ)
}

pub fn key_exists(hive: Hive, path: &str) -> bool {
    open_read(hive, path).is_ok()
}

pub fn get_string(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub fn get_dword(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

pub fn has_value(key: &RegKey, name: &str) -> bool {
    key.get_raw_value(name).is_ok()
}

pub fn delete_value(hive: Hive, path: &str, name: &str) -> Result<(), String> {
    let key = open(hive, path, KEY_DELETE).map_err(|error| friendly(&error))?;
    key.delete_value(name).map_err(|error| friendly(&error))
}

pub fn delete_key(hive: Hive, path: &str) -> Result<(), String> {
    let (parent_path, name) = split_path(path)
        .ok_or_else(|| "invalid key path (no subkey name)".to_string())?;
    let parent = if parent_path.is_empty() {
        hive.key()
    } else {
        open(hive, parent_path, KEY_DELETE).map_err(|error| friendly(&error))?
    };

    match parent.open_subkey_with_flags(name, KEY_DELETE) {
        Ok(target) => {
            delete_tree(&target)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err("key not found (it may already have been removed)".to_string());
        }
        Err(error) => return Err(friendly(&error)),
    }

    parent
        .delete_subkey(name)
        .map_err(|error| friendly(&error))
}

fn delete_tree(key: &RegKey) -> Result<(), String> {
    let values: Vec<String> = key
        .enum_values()
        .filter_map(Result::ok)
        .map(|(name, _)| name)
        .collect();
    for value in values {
        key.delete_value(&value)
            .map_err(|error| friendly(&error))?;
    }

    let subkeys: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();
    for subkey in subkeys {
        {
            let child = key
                .open_subkey_with_flags(&subkey, KEY_DELETE)
                .map_err(|error| friendly(&error))?;
            delete_tree(&child)?;
        }
        key.delete_subkey(&subkey)
            .map_err(|error| friendly(&error))?;
    }
    Ok(())
}

fn split_path(path: &str) -> Option<(&str, &str)> {
    let path = path.trim_matches('\\');
    if path.is_empty() {
        return None;
    }
    match path.rsplit_once('\\') {
        Some((parent, name)) if !name.is_empty() => Some((parent, name)),
        Some(_) => None,
        None => Some(("", path)),
    }
}

pub fn friendly(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(5) => {
            "access denied; for HKLM keys, run the terminal as administrator".to_string()
        }
        Some(2) => "key or value not found".to_string(),
        Some(32) => "the key is in use by another process".to_string(),
        _ => error.to_string(),
    }
}

/// Checks the current process elevation token (does not attempt elevation).
pub fn is_admin() -> bool {
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Full names used in the header of a .reg file.
pub fn hive_regedit_name(hive: Hive) -> &'static str {
    hive.regedit_name()
}
