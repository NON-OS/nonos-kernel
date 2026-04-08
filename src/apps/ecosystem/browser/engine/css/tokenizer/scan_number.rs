extern crate alloc;
use alloc::string::String;
use super::token_types::CssToken;

pub fn scan_numeric(bytes: &[u8], start: usize) -> (CssToken, usize) {
    let (num_str, mut i) = consume_number_chars(bytes, start);
    let value: f32 = num_str.parse().unwrap_or(0.0);

    if i < bytes.len() && bytes[i] == b'%' {
        return (CssToken::Percentage(value), i + 1);
    }

    if i < bytes.len() && is_ident_start(bytes[i]) {
        let unit_start = i;
        while i < bytes.len() && is_ident_char(bytes[i]) {
            i += 1;
        }
        let unit = String::from_utf8_lossy(&bytes[unit_start..i]).into_owned();
        return (CssToken::Dimension(value, unit), i);
    }

    (CssToken::Number(value), i)
}

fn consume_number_chars(bytes: &[u8], start: usize) -> (String, usize) {
    let mut i = start;
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    let s = String::from_utf8_lossy(&bytes[start..i]).into_owned();
    (s, i)
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'-'
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
