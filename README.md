# RegClean

**RegClean** is a safe, portable Windows Registry scanner and cleaner. It looks for broken references left behind by removed or moved applications, shows the risk of every finding, and removes only what you select. Before changing anything, it writes **one `.reg` backup containing every selected entry** to the portable `backup` folder.

The project ships two executables:

- `regclean.exe` — scriptable command-line interface.
- `regclean-gui.exe` — native desktop interface.

Both are Windows GUI/console programs with `CleanReg.ico` embedded. There is no installer, service, driver, or background process.

## Highlights

- Read-only scanning by default; fixing requires explicit selection and confirmation.
- One `.reg` backup per cleanup, written **after confirmation and before the first removal**.
- If creating the backup fails, nothing is removed.
- Restore the whole cleanup with one command, or with **Undo last fix** in the GUI.
- Portable data: backups and exclusions live next to the executable, not in `AppData`.
- Risk levels and a system/vendor allowlist reduce destructive mistakes.
- JSON output and stable finding IDs for scripting.

## Portable layout

Keep the executables in a writable folder. For example:

```text
RegClean\
  regclean.exe
  regclean-gui.exe
  README.md
  LICENSE
  backup\
    regclean-20261105-143012.reg
  regclean-exclusions.txt
```

Default locations, relative to the folder containing the running executable:

| Data | Location |
| --- | --- |
| Backup | `<exe folder>\backup\regclean-YYYYMMDD-HHMMSS.reg` |
| Exclusions | `<exe folder>\regclean-exclusions.txt` |

The release executables depend only on Windows system DLLs and the Windows C runtime. No MinGW or Visual C++ runtime DLL needs to be copied alongside them. The app does not write to `%APPDATA%`, `%LOCALAPPDATA%`, or the registry for its own settings.

Use `--backup-dir` if you intentionally want the single backup file somewhere else.

## Download

Download the portable Windows x64 zip from the repository’s **Releases** page. Extract it to a writable folder and run either executable. No installation is required.

## Quick start

### GUI

Run `regclean-gui.exe`:

1. Choose the scan categories.
2. Click **Scan**.
3. Review the risk and target of each finding; medium-risk items are preselected.
4. Click **Fix selected** and confirm.
5. The GUI writes one backup file and then removes the selected entries.
6. Use **Undo last fix** to import that backup.

Run the GUI as administrator if you need to fix entries under `HKLM`.

### CLI

```text
regclean scan
regclean scan --category uninstall --category startup
regclean fix --max-risk low
regclean fix --only 13ffeaa7 --yes
regclean restore "backup\regclean-20261105-143012.reg"
regclean categories
regclean exclude add "HKLM\SOFTWARE\Vendor\"
regclean exclude list
```

`scan` and `fix` print their findings before asking for confirmation. `fix` defaults to a maximum risk of `medium`; use `--max-risk low` to be more conservative or `--max-risk high` to include everything.

Useful options:

```text
--json                 Machine-readable output
--no-color             Disable ANSI colors
--exclude PREFIX       Ignore matching targets for this run
--no-allowlist         Disable the system/vendor allowlist
--dry-run              Show what fix would do; no backup or removal
--yes                  Skip confirmation (required with --json)
--backup-dir DIR       Store the single backup in another directory
--fail-on-findings     scan exits 1 when anything is found
```

## Backup and undo

A cleanup creates exactly one file, for example:

```text
backup\regclean-20261105-143012.reg
```

It contains all selected values and keys, including whole key trees when a finding targets a key. The file is created only after the confirmation prompt and before the first deletion. If the export fails, the cleanup stops before touching the registry.

Restore it with:

```text
regclean restore "backup\regclean-20261105-143012.reg"
```

Importing a `.reg` file merges keys and values into the current registry. It can overwrite a newer value with an older one, so review the target before restoring. Restoring an `HKLM` backup requires an elevated terminal.

## What it checks

| Category | What is checked |
| --- | --- |
| `uninstall` | Programs and Features entries whose uninstaller points to a missing file. |
| `startup` | `Run` / `RunOnce` values whose executable is missing. |
| `app-paths` | `App Paths` registrations whose default executable is missing. |
| `applications` | `Applications\<exe>\shell\<verb>\command` entries. A whole application key is removed only when every existing command is broken and none is unverifiable. |
| `com` | `InprocServer32`, `LocalServer32`, and `InprocHandler32` values pointing to missing files. Only the server subkey is targeted, never the whole CLSID. |
| `prog-ids` | File extensions pointing to missing ProgIDs, and orphaned `OpenWithProgids` values. |
| `help-files` | Type library `HELPDIR` keys whose documentation path is missing. |
| `app-compat` | Compatibility Assistant cache entries whose executable no longer exists. |
| `installer` | Windows Installer folder registrations pointing to missing directories. |
| `shell-extensions` | Approved shell extensions whose CLSID is no longer registered. |
| `services` | Service `ImagePath` values pointing to a missing program (high risk). |
| `fonts` | `Fonts` values whose font file is missing. |
| `shared-dlls` | `SharedDLLs` counters whose file is missing. |
| `mui-cache` | User `MuiCache` application paths that no longer exist. |

RegClean deliberately skips unverifiable paths (URLs, UNC paths, relative paths, unexpanded variables, and paths on disconnected drives) and system/vendor locations unless you disable the allowlist. Services are the exception: their `ImagePath` is checked directly and reported as high risk because a service registration is only meaningful with a working binary.

## Report coverage

These checks cover the broken-reference entries seen in a local Revo Registry Cleaner report while keeping RegClean’s conservative model:

- Covered from that report: missing CLSID `AppID`/ProgID references, TypeLib help folders, Compatibility Assistant paths, Windows Installer folders, approved shell extensions, service binaries, uninstaller `DisplayIcon`/`InstallSource`, empty uninstall keys, and the existing COM, ProgID, font, shared-DLL, MUI-cache, startup, App Paths, and Applications checks.
- Intentionally not cleaned: MRU/history lists, empty file-extension keys, audio-policy caches, firewall rules, and software-specific recent-file lists. These are privacy or configuration data rather than high-confidence broken references, and some are security-sensitive.
- MuiCache is reported only when the executable path is actually missing. “Missing MUI resource” entries for programs that still exist are not treated as broken.

## Risk levels

- **Low** — an isolated value or command points to a missing file.
- **Medium** — a whole application or COM server key is targeted; review before fixing.
- **High** — the installer is missing but the install folder still exists, or a service points to a missing binary.

The default maximum risk is **medium**. High-risk findings require `fix --max-risk high` or manual selection in the GUI. Service findings are never preselected in the GUI.

## Administrator access

| Area | Standard user | Administrator |
| --- | --- | --- |
| Scan `HKCU` | Yes | Yes |
| Scan `HKLM` | Partially, depending on ACLs | Yes |
| Fix `HKCU` | Yes | Yes |
| Fix `HKLM` | No | Yes |
| Restore an `HKLM` backup | No | Yes |

`shared-dlls`, `installer`, and `services` are under `HKLM`; `mui-cache`, `app-compat`, and `help-files` (per-user registrations) can be under `HKCU`. RegClean never attempts to elevate itself.

## Build from source

Requirements:

- Windows 10 or later.
- A Rust toolchain with the `x86_64-pc-windows-gnu` target.
- MinGW `windres` on `PATH` so the build script can embed `CleanReg.ico`.

```text
cargo check --all-targets
cargo test
cargo build --release
```

The release build produces:

```text
target\release\regclean.exe
target\release\regclean-gui.exe
```

`build.rs` uses `winresource` to embed `CleanReg.ico` and version metadata into both binaries. The release profile uses thin LTO and strips symbols.

## Safety model

1. Scanning is read-only.
2. The selected findings are shown before any change.
3. Confirmation is required unless `--yes` is passed.
4. One complete `.reg` backup is written after confirmation.
5. If backup creation fails, the cleanup is aborted.
6. Entries are removed one by one; failures are reported without pretending they succeeded.
7. The backup stays in the portable `backup` folder until you delete it.

This is not a substitute for a full registry or system backup. Review medium- and high-risk findings, and keep important machine backups.

## Limitations

- Windows only.
- RegClean checks registry references; it does not uninstall applications or delete leftover files.
- Some valid registrations use paths that cannot be verified offline; those are skipped rather than flagged.
- A `.reg` restore merges data and may overwrite newer values.
- Registry permissions can still deny an individual removal even when the app is elevated.

## License

MIT. See [LICENSE](LICENSE).
