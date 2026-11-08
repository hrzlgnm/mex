mod app;
mod browse;
mod ui;

use anyhow::Result;

fn main() -> Result<()> {
    let mut terminal = ui::try_init()?;
    let has_tui = terminal.is_some();
    let mut app = app::App::new()?;
    let res = app.run(&mut terminal);
    ui::try_restore(has_tui)?;
    res
}
