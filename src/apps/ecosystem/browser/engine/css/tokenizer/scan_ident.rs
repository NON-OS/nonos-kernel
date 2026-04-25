extern crate alloc;
use super::token_types::CssToken;
use alloc::string::String;

pub fn scan_ident_or_function(bytes: &[u8], start: usize) -> (Option<CssToken>, usize) {
    let (name, end) = scan_ident_chars(bytes, start);
    if end < bytes.len() && bytes[end] == b'(' {
        return (Some(CssToken::Function(name)), end + 1);
    }
    (Some(CssToken::Ident(name)), end)
}

pub fn scan_ident_chars(bytes: &[u8], start: usize) -> (String, usize) {
    let mut i = start;
    while i < bytes.len() && is_ident_char(bytes[i]) {
        i += 1;
    }
    (String::from_utf8_lossy(&bytes[start..i]).into_owned(), i)
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
