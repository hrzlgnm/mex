mod anomalies;
mod app;
mod browse;
mod dump;
mod ui;

use anyhow::Result;
use clap::Parser;

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

    /// Write log output to this file (appended). Without it, headless
    /// mode logs warnings to stderr and TUI mode discards logs.
    #[arg(long, value_name = "PATH")]
    log_file: Option<String>,
}

/// Minimal log sink with no new dependencies. The file sink (if
/// `--log-file` is given) records Info and above; headless stderr gets
/// Warn and above so routine traffic stays quiet. TUI mode without a
/// file installs no logger at all — writing to the terminal would
/// corrupt the interface.
struct MexLogger {
    file: Option<std::sync::Mutex<std::fs::File>>,
    stderr: bool,
}

impl MexLogger {
    fn install(file: Option<std::fs::File>, stderr: bool) {
        let logger = Box::leak(Box::new(MexLogger {
            file: file.map(std::sync::Mutex::new),
            stderr,
        }));
        // A test binary shares one process-wide logger: first install
        // wins, later ones are ignored.
        let _ = log::set_logger(logger);
        log::set_max_level(log::LevelFilter::Info);
    }
}

impl log::Log for MexLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if self.file.is_some() {
            metadata.level() <= log::Level::Info
        } else {
            self.stderr && metadata.level() <= log::Level::Warn
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
        if let Some(f) = &self.file {
            if let Ok(mut f) = f.lock() {
                let _ = std::io::Write::write_all(&mut *f, line.as_bytes());
            }
        }
        if self.stderr {
            eprint!("{line}");
        }
    }

    fn flush(&self) {}
}

/// Install logging before the app runs: `--log-file` wins in both
/// modes (single sink, appended); otherwise headless mode logs
/// warnings to stderr (AGENTS.md) and TUI mode discards logs.
fn init_logging(log_file: Option<&str>, has_tui: bool) -> Result<()> {
    match (log_file, has_tui) {
        (Some(path), _) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| anyhow::anyhow!("cannot open log file {path}: {e}"))?;
            MexLogger::install(Some(file), false);
        }
        (None, false) => MexLogger::install(None, true),
        (None, true) => {}
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let interfaces = match args.interfaces {
        Some(ifs) => Some(browse::validate_selection(
            &ifs,
            &browse::available_interfaces(),
        )?),
        None => None,
    };
    let mut terminal = ui::try_init()?;
    let has_tui = terminal.is_some();
    init_logging(args.log_file.as_deref(), has_tui)?;
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
    fn file_sink_records_warnings() {
        let path = std::env::temp_dir().join(format!("mex-log-test-{}.log", std::process::id()));
        // Unique path per process: parallel `cargo test` runs never share it.
        let _ = std::fs::remove_file(&path);
        super::init_logging(Some(path.to_str().unwrap()), false).unwrap();
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
