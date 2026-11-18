use super::*;

/// Minimal log sink with no new dependencies. The file sink (if
/// `--log-file` is given) records Info and above; headless stderr gets
/// Warn and above so routine traffic stays quiet. TUI mode without a
/// file installs no logger at all — writing to the terminal would
/// corrupt the interface.
/// Mutable logger state. Held in a global so `init_logging` can reconfigure
/// thresholds and sinks even after the (process-wide, first-wins) logger has
/// been installed; this keeps level changes observable in tests.
pub(super) struct LoggerState {
    pub(super) file: Option<std::sync::Mutex<RotatingLog>>,
    pub(super) file_level: log::LevelFilter,
    pub(super) stderr: bool,
    pub(super) stderr_level: log::LevelFilter,
}

pub(super) static LOGGER_STATE: std::sync::Mutex<LoggerState> =
    std::sync::Mutex::new(LoggerState {
        file: None,
        file_level: log::LevelFilter::Info,
        stderr: false,
        stderr_level: log::LevelFilter::Warn,
    });

pub(super) struct MexLogger;

pub(super) static LOGGER: MexLogger = MexLogger;

impl MexLogger {
    pub(super) fn install(
        file: Option<RotatingLog>,
        stderr: bool,
        log_level: Option<log::LevelFilter>,
    ) {
        let (file_level, stderr_level) = match log_level {
            Some(level) => (level, level),
            None => (log::LevelFilter::Info, log::LevelFilter::Warn),
        };
        let max_level = log_level.unwrap_or(log::LevelFilter::Info);
        if let Ok(mut state) = LOGGER_STATE.lock() {
            state.file = file.map(std::sync::Mutex::new);
            state.file_level = file_level;
            state.stderr = stderr;
            state.stderr_level = stderr_level;
        }
        // A test binary shares one process-wide logger: first install
        // wins, later ones are ignored, but the state above is always
        // updated.
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(max_level);
    }
}

/// Last retained log write failure, if any. Global because the logger
/// is a leaked static and cannot be downcast through `dyn log::Log`.
pub(super) static LAST_LOG_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Take the last retained write failure, if any.
pub fn take_log_error() -> Option<String> {
    LAST_LOG_ERROR.lock().ok().and_then(|mut e| e.take())
}

impl log::Log for MexLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if let Ok(state) = LOGGER_STATE.lock() {
            (state.file.is_some() && metadata.level() <= state.file_level)
                || (state.stderr && metadata.level() <= state.stderr_level)
        } else {
            false
        }
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} [{}] {}\n",
            chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
            record.level(),
            record.args()
        );
        if let Ok(state) = LOGGER_STATE.lock() {
            if state.file.is_some() && record.metadata().level() <= state.file_level {
                if let Some(f) = &state.file {
                    if let Ok(mut f) = f.lock() {
                        if let Err(e) = f.write_line(&line) {
                            if let Ok(mut le) = LAST_LOG_ERROR.lock() {
                                *le = Some(format!("log write failed: {e}"));
                            }
                        }
                    }
                }
            }
            if state.stderr && record.metadata().level() <= state.stderr_level {
                eprint!("{line}");
            }
        }
    }

    fn flush(&self) {}
}

pub(super) const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

pub(super) const KEEP_LOG_GENERATIONS: u32 = 3;

/// Size-based log rotation: `mex.log` plus `mex.log.1..N` backups.
pub(super) struct RotatingLog {
    /// `None` only while closed for renaming: Windows cannot rename an
    /// open file, so `rotate` drops the handle first.
    pub(super) file: Option<std::fs::File>,
    pub(super) path: std::path::PathBuf,
    pub(super) written: u64,
    pub(super) max_bytes: u64,
    pub(super) keep: u32,
}

impl RotatingLog {
    pub(super) fn open(path: &std::path::Path, max_bytes: u64, keep: u32) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut log = Self {
            file: Some(Self::append(path)?),
            path: path.to_path_buf(),
            written: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            max_bytes,
            keep,
        };
        if log.written >= max_bytes {
            log.rotate()?;
        }
        Ok(log)
    }

    pub(super) fn append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }

    /// Backup path `mex.log.N` for generation `n`.
    pub(super) fn backup_path(&self, n: u32) -> std::path::PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{n}"));
        self.path.with_file_name(name)
    }

    /// Append one line, rotating first when it would exceed the cap, so
    /// the live file stays bounded.
    pub(super) fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        if self.written + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        if let Some(f) = self.file.as_mut() {
            use std::io::Write;
            f.write_all(line.as_bytes())?;
            self.written += line.len() as u64;
        }
        Ok(())
    }

    /// Shift generations down (`mex.log` -> `.1` -> `.2` ...) and reopen a
    /// fresh live file. Missing generations are skipped; rename targets
    /// are removed first for Windows, where rename will not replace.
    pub(super) fn rotate(&mut self) -> std::io::Result<()> {
        // Close before renaming: Windows cannot rename an open file.
        self.file.take();
        for i in (1..=self.keep).rev() {
            let from = if i == 1 {
                self.path.clone()
            } else {
                self.backup_path(i - 1)
            };
            if from.exists() {
                let to = self.backup_path(i);
                let _ = std::fs::remove_file(&to);
                std::fs::rename(&from, &to)?;
            }
        }
        self.file = Some(Self::append(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

/// Default log directory: XDG state dir on Linux
/// (`$XDG_STATE_HOME/mex`, else `~/.local/state/mex`), `~/Library/Logs`
/// on macOS, `%LOCALAPPDATA%` on Windows, temp dir as a last resort.
pub(super) fn default_log_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        return std::path::PathBuf::from(dir).join(APP_NAME).join("logs");
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join("Library")
            .join("Logs")
            .join(APP_NAME);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        if !state.is_empty() {
            return std::path::PathBuf::from(state).join(APP_NAME);
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(APP_NAME);
    }
    std::env::temp_dir().join(APP_NAME)
}

/// Install logging before the app runs: an explicit `--log-file`
/// overrides the default `mex.log` in the platform log directory;
/// headless mode also keeps stderr warnings. A bad explicit path fails
/// fast; an unusable default directory degrades to stderr-only
/// (headless) or silent (TUI, where printing would corrupt the UI).
pub(super) fn init_logging(
    log_file: Option<&str>,
    has_tui: bool,
    log_level: Option<log::LevelFilter>,
) -> Result<()> {
    let (path, stderr) = match log_file {
        Some(p) => (std::path::PathBuf::from(p), false),
        None => (default_log_dir().join(format!("{APP_NAME}.log")), !has_tui),
    };
    match RotatingLog::open(&path, MAX_LOG_BYTES, KEEP_LOG_GENERATIONS) {
        Ok(log) => {
            MexLogger::install(Some(log), stderr, log_level);
            Ok(())
        }
        Err(e) if log_file.is_some() => Err(anyhow::anyhow!(
            "cannot open log file {}: {e}",
            path.display()
        )),
        Err(e) => {
            if stderr {
                eprintln!(
                    "mex: cannot open log file {}: {e}; continuing with stderr only",
                    path.display()
                );
                MexLogger::install(None, true, log_level);
            }
            Ok(())
        }
    }
}
