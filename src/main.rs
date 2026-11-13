mod anomalies;
mod app;
mod browse;
mod dump;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(
    name = "mex",
    version,
    about = "Terminal UI to browse and debug mDNS/DNS-SD on the local link — live services, records, queries, and raw packets"
)]
struct Args {
    /// Listen only: never transmit queries, just observe announcements
    #[arg(long)]
    passive: bool,

    /// Network interfaces to use for mDNS discovery
    #[arg(
        long,
        short,
        value_delimiter = ',',
        help = "Network interfaces to use for mDNS discovery (e.g., br0, eth0)"
    )]
    interfaces: Option<Vec<String>>,

    /// Override the default log file. Appended; rotated past 5 MiB
    /// with 3 backups kept.
    #[arg(
        long,
        value_name = "PATH",
        help = "Override the default log file",
        long_help = "Override the default log file (state-dir mex.log on Linux, ~/Library/Logs/mex on macOS, %LOCALAPPDATA%\\mex\\logs on Windows). Appended; rotated past 5 MiB with 3 backups kept. Without it, both modes log to the default file; headless mode additionally logs warnings to stderr, TUI mode without a usable log directory discards logs."
    )]
    log_file: Option<String>,

    /// Minimum log level recorded by every active sink (off, error, warn,
    /// info, debug, trace). Omitted: file sink keeps `info`, headless
    /// stderr keeps `warn`.
    #[arg(
        long,
        value_name = "LEVEL",
        value_parser = parse_log_level,
        help = "Minimum log level recorded by every active sink",
        long_help = "Minimum log level recorded by every active sink (off, error, warn, info, debug, trace). When omitted, the file sink records info and above and headless stderr records warn and above, as before. When provided, the chosen level applies to all active sinks."
    )]
    log_level: Option<log::LevelFilter>,
}

/// Minimal log sink with no new dependencies. The file sink (if
/// `--log-file` is given) records Info and above; headless stderr gets
/// Warn and above so routine traffic stays quiet. TUI mode without a
/// file installs no logger at all — writing to the terminal would
/// corrupt the interface.
/// Mutable logger state. Held in a global so `init_logging` can reconfigure
/// thresholds and sinks even after the (process-wide, first-wins) logger has
/// been installed; this keeps level changes observable in tests.
struct LoggerState {
    file: Option<std::sync::Mutex<RotatingLog>>,
    file_level: log::LevelFilter,
    stderr: bool,
    stderr_level: log::LevelFilter,
}

static LOGGER_STATE: std::sync::Mutex<LoggerState> = std::sync::Mutex::new(LoggerState {
    file: None,
    file_level: log::LevelFilter::Info,
    stderr: false,
    stderr_level: log::LevelFilter::Warn,
});

struct MexLogger;

static LOGGER: MexLogger = MexLogger;

impl MexLogger {
    fn install(file: Option<RotatingLog>, stderr: bool, log_level: Option<log::LevelFilter>) {
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
static LAST_LOG_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

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

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const KEEP_LOG_GENERATIONS: u32 = 3;

/// Size-based log rotation: `mex.log` plus `mex.log.1..N` backups.
struct RotatingLog {
    /// `None` only while closed for renaming: Windows cannot rename an
    /// open file, so `rotate` drops the handle first.
    file: Option<std::fs::File>,
    path: std::path::PathBuf,
    written: u64,
    max_bytes: u64,
    keep: u32,
}

impl RotatingLog {
    fn open(path: &std::path::Path, max_bytes: u64, keep: u32) -> std::io::Result<Self> {
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

    fn append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }

    /// Backup path `mex.log.N` for generation `n`.
    fn backup_path(&self, n: u32) -> std::path::PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{n}"));
        self.path.with_file_name(name)
    }

    /// Append one line, rotating first when it would exceed the cap, so
    /// the live file stays bounded.
    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
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
    fn rotate(&mut self) -> std::io::Result<()> {
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
fn default_log_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        return std::path::PathBuf::from(dir).join("mex").join("logs");
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join("Library")
            .join("Logs")
            .join("mex");
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        if !state.is_empty() {
            return std::path::PathBuf::from(state).join("mex");
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("mex");
    }
    std::env::temp_dir().join("mex")
}

/// Install logging before the app runs: an explicit `--log-file`
/// overrides the default `mex.log` in the platform log directory;
/// headless mode also keeps stderr warnings. A bad explicit path fails
/// fast; an unusable default directory degrades to stderr-only
/// (headless) or silent (TUI, where printing would corrupt the UI).
fn init_logging(
    log_file: Option<&str>,
    has_tui: bool,
    log_level: Option<log::LevelFilter>,
) -> Result<()> {
    let (path, stderr) = match log_file {
        Some(p) => (std::path::PathBuf::from(p), false),
        None => (default_log_dir().join("mex.log"), !has_tui),
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

fn parse_log_level(value: &str) -> Result<log::LevelFilter, String> {
    log::LevelFilter::from_str(value).map_err(|_| format!("invalid log level: {value}"))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let interfaces = match args.interfaces.as_ref() {
        Some(ifs) => Some(browse::validate_selection(
            ifs,
            &browse::available_interfaces(),
        )?),
        None => None,
    };
    let mut terminal = ui::try_init()?;
    let has_tui = terminal.is_some();
    if let Err(e) = init_logging(args.log_file.as_deref(), has_tui, args.log_level) {
        ui::try_restore(has_tui)?;
        return Err(e);
    }
    if args.interfaces.is_some() {
        log::info!("mex: interface selection: {:?}", args.interfaces);
    }
    if args.passive {
        log::info!("mex: passive mode (no queries)");
    }
    if has_tui {
        log::info!("mex: starting in TUI mode");
    }
    let mut app = if args.passive {
        app::App::new_with(true, interfaces)?
    } else if let Some(sel) = interfaces {
        app::App::new_with(false, Some(sel))?
    } else {
        app::App::new()?
    };
    let res = app.run(&mut terminal);
    ui::try_restore(has_tui)?;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that reconfigure the process-wide logger, avoiding
    /// cross-test races on the shared sink state.
    static TEST_LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn passive_flag_parses() {
        let args = Args::try_parse_from(["mex"]).unwrap();
        assert!(!args.passive);
        let args = Args::try_parse_from(["mex", "--passive"]).unwrap();
        assert!(args.passive);
    }

    #[test]
    fn interfaces_flag_parses() {
        let args = Args::try_parse_from(["mex"]).unwrap();
        assert!(args.interfaces.is_none());
        let args = Args::try_parse_from(["mex", "-i", "eth0,br0"]).unwrap();
        assert_eq!(
            args.interfaces,
            Some(vec!["eth0".to_string(), "br0".to_string()])
        );
        let args =
            Args::try_parse_from(["mex", "--interfaces", "eth0", "--interfaces", "br0"]).unwrap();
        assert_eq!(
            args.interfaces,
            Some(vec!["eth0".to_string(), "br0".to_string()])
        );
    }

    #[test]
    fn log_file_flag_parses() {
        let args = Args::try_parse_from(["mex"]).unwrap();
        assert!(args.log_file.is_none());
        let args = Args::try_parse_from(["mex", "--log-file", "/tmp/mex.log"]).unwrap();
        assert_eq!(args.log_file.as_deref(), Some("/tmp/mex.log"));
    }

    #[test]
    fn log_level_threshold_filters_file_sink() {
        let _guard = TEST_LOG_LOCK.lock().unwrap();
        let mk = |suffix: &str| {
            std::env::temp_dir().join(format!(
                "mex-loglevel-{}-{}.log",
                suffix,
                std::process::id()
            ))
        };

        // warn: error+warn recorded, info dropped.
        let path = mk("warn");
        let _ = std::fs::remove_file(&path);
        super::init_logging(
            Some(path.to_str().unwrap()),
            false,
            Some(log::LevelFilter::Warn),
        )
        .unwrap();
        log::error!("probe-warn-error");
        log::warn!("probe-warn-warn");
        log::info!("probe-warn-info");
        let logged = std::fs::read_to_string(&path).unwrap();
        assert!(logged.contains("probe-warn-error"));
        assert!(logged.contains("probe-warn-warn"));
        assert!(!logged.contains("probe-warn-info"));

        // debug: debug recorded, trace not (max level stops it).
        let path = mk("debug");
        let _ = std::fs::remove_file(&path);
        super::init_logging(
            Some(path.to_str().unwrap()),
            false,
            Some(log::LevelFilter::Debug),
        )
        .unwrap();
        log::debug!("probe-debug-debug");
        log::trace!("probe-debug-trace");
        let logged = std::fs::read_to_string(&path).unwrap();
        assert!(logged.contains("probe-debug-debug"));
        assert!(!logged.contains("probe-debug-trace"));

        // trace: trace recorded.
        let path = mk("trace");
        let _ = std::fs::remove_file(&path);
        super::init_logging(
            Some(path.to_str().unwrap()),
            false,
            Some(log::LevelFilter::Trace),
        )
        .unwrap();
        log::trace!("probe-trace-trace");
        let logged = std::fs::read_to_string(&path).unwrap();
        assert!(logged.contains("probe-trace-trace"));

        for suffix in ["warn", "debug", "trace"] {
            let _ = std::fs::remove_file(mk(suffix));
        }
    }

    #[test]
    fn log_level_flag_parses() {
        let args = Args::try_parse_from(["mex"]).unwrap();
        assert!(args.log_level.is_none());
        let args = Args::try_parse_from(["mex", "--log-level", "debug"]).unwrap();
        assert_eq!(args.log_level, Some(log::LevelFilter::Debug));
        let args = Args::try_parse_from(["mex", "--log-level", "TRACE"]).unwrap();
        assert_eq!(args.log_level, Some(log::LevelFilter::Trace));
        assert!(Args::try_parse_from(["mex", "--log-level", "nope"]).is_err());
    }

    #[test]
    fn default_log_dir_respects_xdg_state_home() {
        // Scoped env override: no other test reads these vars.
        let tmp = std::env::temp_dir().join(format!("mex-logdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let old = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_STATE_HOME", &tmp);
        let dir = super::default_log_dir();
        match old {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        assert_eq!(dir, tmp.join("mex"));
        assert!(dir.ends_with("mex"));
    }

    #[test]
    fn rotating_log_caps_size_and_generations() {
        let dir = std::env::temp_dir().join(format!("mex-logrot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("mex.log");
        let mut log = super::RotatingLog::open(&path, 200, 2).unwrap();
        for i in 0..50 {
            log.write_line(&format!(
                "line {i:02} with padding to grow fast 0123456789\n"
            ))
            .unwrap();
        }
        drop(log);
        // Current file stays under the cap; at most 2 backups exist.
        assert!(std::fs::metadata(&path).unwrap().len() <= 200,);
        assert!(dir.join("mex.log.1").exists());
        assert!(!dir.join("mex.log.3").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotating_log_rotates_oversized_file_at_open() {
        // Pre-existing file over the cap: rotated away before writing,
        // exercising the close-before-rename path Windows requires.
        let dir = std::env::temp_dir().join(format!("mex-logopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("mex.log");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, vec![b'x'; 300]).unwrap();
        let mut log = super::RotatingLog::open(&path, 200, 2).unwrap();
        assert!(dir.join("mex.log.1").exists());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        log.write_line("hello\n").unwrap();
        drop(log);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_sink_records_warnings() {
        let _guard = TEST_LOG_LOCK.lock().unwrap();
        let path = std::env::temp_dir().join(format!("mex-log-test-{}.log", std::process::id()));
        // Unique path per process: parallel `cargo test` runs never share it.
        let _ = std::fs::remove_file(&path);
        super::init_logging(Some(path.to_str().unwrap()), false, None).unwrap();
        log::warn!("sink-probe-xyz");
        log::info!("sink-probe-info-xyz");
        let logged = std::fs::read_to_string(&path).unwrap();
        assert!(logged.contains("[WARN]"), "got: {logged}");
        assert!(logged.contains("sink-probe-xyz"), "got: {logged}");
        assert!(logged.contains("sink-probe-info-xyz"), "got: {logged}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn standard_flags_exist() {
        use clap::error::ErrorKind;
        for flag in ["--help", "-h"] {
            let err = Args::try_parse_from(["mex", flag]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DisplayHelp);
        }
        for flag in ["--version", "-V"] {
            let err = Args::try_parse_from(["mex", flag]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        }
    }
}
