use std::sync::atomic::{AtomicBool, Ordering};
static VERBOSE: AtomicBool = AtomicBool::new(false);
pub fn set_verbose(enabled: bool) {
    VERBOSE.store(enabled, Ordering::Relaxed);
}
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}
pub fn message(text: &str, code: u8) {
    use std::io::IsTerminal;
    println!(
        "{}",
        paint(text, code, color_enabled(std::io::stdout().is_terminal()))
    );
}
pub fn log(text: &str, code: u8) {
    use std::io::IsTerminal;
    eprintln!(
        "{}",
        paint(text, code, color_enabled(std::io::stderr().is_terminal()))
    );
}

use std::time::{SystemTime, UNIX_EPOCH};

pub fn color_enabled(terminal: bool) -> bool {
    terminal
        && std::env::var_os("NO_COLOR").is_none()
        && !std::env::var("TERM").is_ok_and(|term| term == "dumb")
}

pub fn paint(text: &str, code: u8, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
