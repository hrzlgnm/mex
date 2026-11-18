// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

mod anomalies;
mod app;
mod browse;
mod devices;
mod dump;
mod logging;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::str::FromStr;

pub use logging::take_log_error;
use logging::*;

/// Program name, from Cargo: the CLI name, the log/state directory and
/// log file names, and the dump's `application_name` all derive from it.
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Parser, Debug)]
#[command(
    name = APP_NAME,
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
