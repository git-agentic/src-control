//! Making untrusted text safe to print to a terminal.

use std::borrow::Cow;

/// Replace control characters in text that came from a peer or from stored objects (a server's error
/// string, a commit author or message) with a visible escape, so it cannot drive the terminal with
/// ANSI/OSC sequences or reorder what is shown with bidi controls. `\n` and `\t` pass through. C0
/// controls and DEL print as `\x1b`, C1, bidi and other invisible format characters as `\u{202e}`.
/// Format-time only: stored data is never changed.
pub fn sanitize_display(s: &str) -> Cow<'_, str> {
    escape(s, false)
}

/// [`sanitize_display`] for text printed inside one line (a `sc log` row, a list row): `\n`, `\r`
/// and `\t` are escaped too, so a commit message cannot start a line that looks like `sc`'s own
/// output, such as a forged signature status.
pub fn sanitize_display_line(s: &str) -> Cow<'_, str> {
    escape(s, true)
}

/// Invisible characters that change how the surrounding text is laid out or read: bidi controls,
/// zero-width characters and the byte-order mark.
fn invisible_format(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

fn escape(s: &str, one_line: bool) -> Cow<'_, str> {
    let bad =
        |c: char| (c.is_control() && (one_line || (c != '\n' && c != '\t'))) || invisible_format(c);
    if !s.chars().any(bad) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if !bad(c) {
            out.push(c);
        } else if (c as u32) < 0x80 {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_ansi_osc_c1_and_del_but_keeps_newline_and_tab() {
        let s = "a\x1b[2Jb\x1b]0;pwn\x07c\u{9b}31m\x7fd\re\nf\tg";
        let out = sanitize_display(s);
        assert_eq!(
            out,
            "a\\x1b[2Jb\\x1b]0;pwn\\x07c\\u{9b}31m\\x7fd\\x0de\nf\tg"
        );
        assert!(!out
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t'));
    }

    #[test]
    fn one_line_form_escapes_newlines_and_bidi_controls() {
        let s = "msg\n    signature: good\r\tx\u{202e}y";
        let out = sanitize_display_line(s);
        assert_eq!(out, "msg\\x0a    signature: good\\x0d\\x09x\\u{202e}y");
        assert_eq!(sanitize_display("a\u{2066}b"), "a\\u{2066}b");
    }

    #[test]
    fn clean_text_is_untouched_and_unallocated() {
        assert!(matches!(sanitize_display("héllo — ok\n"), Cow::Borrowed(_)));
    }
}
