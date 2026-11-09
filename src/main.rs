mod app;
mod browse;
mod ui;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "mex", about = "Browse mDNS/DNS-SD services on the local link")]
struct Args {
    /// Listen only: never transmit queries, just observe announcements
    #[arg(long)]
    passive: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut terminal = ui::try_init()?;
    let has_tui = terminal.is_some();
    let mut app = if args.passive {
        app::App::new_with(true)?
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
}
