//! Making untrusted text safe to print to a terminal.

use std::borrow::Cow;

/// Replace control characters in text that came from a peer or from stored objects (a server's error
/// string, a commit author or message) with a visible escape, so it cannot drive the terminal with
/// ANSI/OSC sequences. `\n` and `\t` pass through. C0 controls and DEL print as `\x1b`, C1 controls
/// as `\u{85}`. Format-time only: stored data is never changed.
pub fn sanitize_display(s: &str) -> Cow<'_, str> {
    let bad = |c: char| c.is_control() && c != '\n' && c != '\t';
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
    fn clean_text_is_untouched_and_unallocated() {
        assert!(matches!(sanitize_display("héllo — ok\n"), Cow::Borrowed(_)));
    }
}
