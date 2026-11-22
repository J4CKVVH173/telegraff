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

/// Human durations retain seconds only where useful, rather than exposing timestamps.
pub fn duration(seconds: u64) -> String {
    if seconds >= 86400 {
        let days = seconds / 86400;
        let hours = seconds % 86400 / 3600;
        if hours == 0 {
            format!("{days}d")
        } else {
            format!("{days}d {hours}h")
        }
    } else if seconds >= 3600 {
        let hours = seconds / 3600;
        let minutes = seconds % 3600 / 60;
        if minutes == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h {minutes}m")
        }
    } else if seconds >= 60 {
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        if seconds == 0 {
            format!("{minutes}m")
        } else {
            format!("{minutes}m {seconds}s")
        }
    } else {
        format!("{seconds}s")
    }
}
pub fn timestamp(timestamp: u64) -> String {
    let date = i64::try_from(timestamp)
        .ok()
        .and_then(|t| time::OffsetDateTime::from_unix_timestamp(t).ok());
    match date {
        Some(date) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            date.year(),
            date.month() as u8,
            date.day(),
            date.hour(),
            date.minute()
        ),
        None => "invalid date".into(),
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;
    #[test]
    fn readable_times_include_units_and_an_explicit_timezone() {
        for (seconds, text) in [
            (0, "0s"),
            (59, "59s"),
            (60, "1m"),
            (166, "2m 46s"),
            (3600, "1h"),
            (3661, "1h 1m"),
            (90000, "1d 1h"),
        ] {
            assert_eq!(duration(seconds), text);
        }
        assert_eq!(timestamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(timestamp(951782400), "2000-02-29 00:00 UTC");
        assert_eq!(timestamp(u64::MAX), "invalid date");
    }
}
