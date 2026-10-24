//! Standard base64 (RFC 4648, padded), for the contents API's file bodies and uploads.

const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `data` with padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decode padded standard base64; ASCII whitespace (line breaks) is ignored. `None` for anything
/// else outside the alphabet, bad padding, or a length that is not a multiple of four.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let val = |b: u8| T.iter().position(|&t| t == b).map(|p| p as u32);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.chunks(4).count();
    for (i, c) in bytes.chunks(4).enumerate() {
        let pad = c.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != chunks) {
            return None;
        }
        let mut n = 0u32;
        for (j, &b) in c.iter().enumerate() {
            n <<= 6;
            if j < 4 - pad {
                n |= val(b)?;
            } else if b != b'=' {
                return None;
            }
        }
        let b3 = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&b3[..3 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_padding_length() {
        for (raw, enc) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"hello\n", "aGVsbG8K"),
        ] {
            assert_eq!(encode(raw), enc);
            assert_eq!(decode(enc).as_deref(), Some(raw));
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)), Some(all));
    }

    #[test]
    fn decode_refuses_malformed_input_and_ignores_line_breaks() {
        assert_eq!(decode("Zm9v\nYg==\n").as_deref(), Some(&b"foob"[..]));
        for bad in ["Zg=", "Z", "Zg==Zg==", "Zm9v!", "=Zg=", "Zm=v", "Zg=a"] {
            assert!(decode(bad).is_none(), "{bad}");
        }
    }
}
