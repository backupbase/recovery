//! Getting the passcode: `--passcode-file`, the `BB_PASSCODE` environment variable, or a
//! prompt that does not show what is typed. The passcode is never printed or logged.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{display, usage, Error, Kind, Result};

pub const ENV: &str = "BB_PASSCODE";

pub enum Source<'a> {
    File(&'a Path),
    Env,
    Prompt,
}

pub fn source(file: Option<&Path>) -> Source<'_> {
    match file {
        Some(f) => Source::File(f),
        None if std::env::var_os(ENV).is_some_and(|v| !v.is_empty()) => Source::Env,
        None => Source::Prompt,
    }
}

/// The first line of a passcode file: UTF-8 (with or without a byte order mark), or UTF-16
/// with a byte order mark (what Windows PowerShell 5.1 writes with `>` and Out-File). A line
/// ends at CR or LF. A NUL means another encoding (UTF-16 without a byte order mark, UTF-32).
fn first_line(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let utf16 = |rest: &[u8], unit: fn([u8; 2]) -> u16| -> Option<Zeroizing<String>> {
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(rest.chunks_exact(2).map(|c| unit([c[0], c[1]])).collect());
        let line: &[u16] = match units.iter().position(|&c| c == u16::from(b'\n') || c == u16::from(b'\r')) {
            Some(i) => &units[..i],
            None if rest.len() % 2 == 0 => &units,
            None => return None,
        };
        String::from_utf16(line).ok().map(Zeroizing::new)
    };
    let line = if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        utf16(rest, u16::from_le_bytes)?
    } else if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        utf16(rest, u16::from_be_bytes)?
    } else {
        let mut s = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes); // a byte order mark (Notepad)
        if let Some(i) = s.iter().position(|&c| c == b'\n' || c == b'\r') {
            s = &s[..i];
        }
        Zeroizing::new(std::str::from_utf8(s).ok()?.to_string())
    };
    (!line.contains('\0')).then_some(line)
}

/// Reads the passcode. With a prompt, `allow_skip` lets an empty answer mean "skip" (None).
pub fn get(src: &Source, label: &str, allow_skip: bool) -> Result<Option<Zeroizing<String>>> {
    let pw = match src {
        Source::File(p) => {
            let mut f = File::open(p).map_err(|e| Error::new(Kind::Io, format!("Could not read the passcode file {}: {}.", display(p), crate::error::reason(&e))))?;
            let mut bytes = Zeroizing::new(Vec::new());
            f.by_ref().take(64 * 1024).read_to_end(&mut bytes).map_err(|e| Error::new(Kind::Io, format!("Could not read the passcode file {}: {}.", display(p), crate::error::reason(&e))))?;
            first_line(&bytes).ok_or_else(|| usage("The passcode file is not UTF-8 or UTF-16 text."))?
        }
        Source::Env => Zeroizing::new(std::env::var(ENV).map_err(|_| usage(format!("{ENV} is not valid text.")))?),
        Source::Prompt => {
            let prompt = if allow_skip { format!("Passcode for \"{label}\" (press Enter to skip): ") } else { format!("Passcode for \"{label}\": ") };
            match rpassword::prompt_password(prompt) {
                Ok(s) => Zeroizing::new(s),
                Err(_) => return Err(usage(format!("No passcode given and none can be asked for here. Set {ENV} or use --passcode-file."))),
            }
        }
    };
    if pw.is_empty() {
        if allow_skip && matches!(src, Source::Prompt) {
            return Ok(None);
        }
        return Err(usage("The passcode is empty."));
    }
    Ok(Some(pw))
}

#[cfg(test)]
mod tests {
    use super::first_line;

    fn utf16(s: &str, bom: [u8; 2], unit: fn(u16) -> [u8; 2]) -> Vec<u8> {
        let mut v = bom.to_vec();
        v.extend(s.encode_utf16().flat_map(unit));
        v
    }

    #[test]
    fn passcode_file_encodings() {
        let want = "Pass wörd ✓ 2026";
        let text = format!("{want}\r\nsecond line\r\n");
        for bytes in [
            text.clone().into_bytes(),
            format!("\u{feff}{text}").into_bytes(),
            format!("{want}\n").into_bytes(),
            want.as_bytes().to_vec(),
            utf16(&text, [0xFF, 0xFE], u16::to_le_bytes),
            utf16(&text, [0xFE, 0xFF], u16::to_be_bytes),
            utf16(want, [0xFF, 0xFE], u16::to_le_bytes),
        ] {
            assert_eq!(first_line(&bytes).as_deref().map(String::as_str), Some(want), "{bytes:?}");
        }
        // UTF-16 without a byte order mark and UTF-32 are refused (they hold NULs).
        assert!(first_line(&want.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>()).is_none());
        assert!(first_line(&want.encode_utf16().flat_map(u16::to_be_bytes).collect::<Vec<_>>()).is_none());
        assert!(first_line(&[&[0xFF, 0xFE, 0, 0][..], &want.chars().flat_map(|c| (c as u32).to_le_bytes()).collect::<Vec<_>>()].concat()).is_none());
        // An odd number of bytes in the first line, an unpaired surrogate, invalid UTF-8.
        assert!(first_line(b"\xFF\xFEa").is_none());
        assert!(first_line(b"\xFF\xFE\x00\xD8a\x00").is_none());
        assert!(first_line(b"a\xFFb").is_none());
        // Only the first line has to be valid; a lone CR ends it too.
        assert_eq!(first_line(b"ok\n\xFF").as_deref().map(String::as_str), Some("ok"));
        assert_eq!(first_line(b"ok\rsecond\r").as_deref().map(String::as_str), Some("ok"));
        assert_eq!(first_line(b"\xFF\xFEo\x00k\x00\n\x00x").as_deref().map(String::as_str), Some("ok"));
    }
}
