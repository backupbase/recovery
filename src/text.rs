//! Plain-text formatting: numbers, sizes, dates (always UTC, so output is the same everywhere).

pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1000.0;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

/// Text from the backup (names, labels) made safe to print: control characters, which could
/// move the cursor or change the terminal, become `?`.
pub fn clean(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().any(char::is_control) {
        std::borrow::Cow::Owned(s.chars().map(|c| if c.is_control() { '?' } else { c }).collect())
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

pub fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", thousands(n), if n == 1 { one } else { many })
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix milliseconds as `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn utc_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// A version id (`20260925T150000Z-3fa9c2d1`) as `2026-09-25 15:00:00 UTC`.
pub fn id_date(id: &str) -> String {
    if id.len() < 15 {
        return id.to_string();
    }
    format!("{}-{}-{} {}:{}:{} UTC", &id[0..4], &id[4..6], &id[6..8], &id[9..11], &id[11..13], &id[13..15])
}

/// An RFC 3339 time as written by the app (`2026-09-25T15:00:00Z`) in the same style.
pub fn rfc3339(s: &str) -> String {
    if s.len() >= 19 && s.as_bytes()[10] == b'T' {
        format!("{} {} UTC", &s[..10], &s[11..19])
    } else {
        s.to_string()
    }
}

pub fn os_label(os: &str) -> String {
    match os {
        "macos" => "macOS".into(),
        "windows" => "Windows".into(),
        "linux" => "Linux".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_234_567), "1.2 MB");
        assert_eq!(utc_ms(0), "1970-01-01 00:00:00");
        assert_eq!(utc_ms(1758812400123), "2025-09-25 15:00:00");
        assert_eq!(utc_ms(-1), "1969-12-31 23:59:59");
        assert_eq!(utc_ms(951_782_400_000), "2000-02-29 00:00:00");
        assert_eq!(id_date("20260925T150000Z-3fa9c2d1"), "2026-09-25 15:00:00 UTC");
        assert_eq!(rfc3339("2026-09-25T15:00:00Z"), "2026-09-25 15:00:00 UTC");
        assert_eq!(clean("a\x1b[2Jb\u{9b}c\td"), "a?[2Jb?c?d");
        assert_eq!(clean("Résumé ✓"), "Résumé ✓");
    }
}
