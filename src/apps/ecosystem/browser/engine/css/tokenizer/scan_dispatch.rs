extern crate alloc;
use super::scan_helpers::{peek_digit, peek_dot_digit, skip_comment, skip_ws};
use super::scan_ident::{scan_ident_chars, scan_ident_or_function};
use super::scan_number::scan_numeric;
use super::scan_string::scan_quoted_string;
use super::token_types::CssToken;

pub fn scan_one(bytes: &[u8], i: usize) -> (Option<CssToken>, usize) {
    let b = bytes[i];
    match b {
        b' ' | b'\t' | b'\n' | b'\r' => (Some(CssToken::Whitespace), skip_ws(bytes, i)),
        b'"' | b'\'' => {
            let (s, end) = scan_quoted_string(bytes, i);
            (Some(CssToken::String(s)), end)
        }
        b'0'..=b'9' => {
            let (tok, end) = scan_numeric(bytes, i);
            (Some(tok), end)
        }
        b'.' if peek_digit(bytes, i + 1) => {
            let (tok, end) = scan_numeric(bytes, i);
            (Some(tok), end)
        }
        b'-' if peek_digit(bytes, i + 1) || peek_dot_digit(bytes, i + 1) => {
            let (tok, end) = scan_numeric(bytes, i);
            (Some(tok), end)
        }
        b'#' => {
            let (name, end) = scan_ident_chars(bytes, i + 1);
            (Some(CssToken::Hash(name)), end)
        }
        b'@' => {
            let (name, end) = scan_ident_chars(bytes, i + 1);
            (Some(CssToken::AtKeyword(name)), end)
        }
        b'/' if bytes.get(i + 1) == Some(&b'*') => (None, skip_comment(bytes, i)),
        _ => scan_punctuation_or_ident(bytes, i, b),
    }
}

fn scan_punctuation_or_ident(bytes: &[u8], i: usize, b: u8) -> (Option<CssToken>, usize) {
    match b {
        b':' => (Some(CssToken::Colon), i + 1),
        b';' => (Some(CssToken::Semicolon), i + 1),
        b',' => (Some(CssToken::Comma), i + 1),
        b'{' => (Some(CssToken::OpenBrace), i + 1),
        b'}' => (Some(CssToken::CloseBrace), i + 1),
        b'(' => (Some(CssToken::OpenParen), i + 1),
        b')' => (Some(CssToken::CloseParen), i + 1),
        b'[' => (Some(CssToken::OpenBracket), i + 1),
        b']' => (Some(CssToken::CloseBracket), i + 1),
        b'.' => (Some(CssToken::Dot), i + 1),
        b'>' => (Some(CssToken::Greater), i + 1),
        b'+' => (Some(CssToken::Plus), i + 1),
        b'~' => (Some(CssToken::Tilde), i + 1),
        b'*' => (Some(CssToken::Star), i + 1),
        _ if b.is_ascii_alphabetic() || b == b'_' || b == b'-' => scan_ident_or_function(bytes, i),
        _ => (Some(CssToken::Delim(b as char)), i + 1),
    }
}
