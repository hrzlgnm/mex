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
