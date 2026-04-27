extern crate alloc;
use super::scan_dispatch::scan_one;
use super::token_types::CssToken;
use alloc::vec::Vec;

pub fn tokenize(input: &str) -> Vec<CssToken> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let (token, next) = scan_one(bytes, i);
        if let Some(t) = token {
            tokens.push(t);
        }
        i = next;
    }
    tokens
}
