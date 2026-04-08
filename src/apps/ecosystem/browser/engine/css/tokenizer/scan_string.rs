extern crate alloc;
use alloc::string::String;

pub fn scan_quoted_string(bytes: &[u8], start: usize) -> (String, usize) {
    let quote = bytes[start];
    let mut result = String::new();
    let mut i = start + 1;

    while i < bytes.len() {
        let b = bytes[i];
        if b == quote {
            return (result, i + 1);
        }
        if b == b'\\' && i + 1 < bytes.len() {
            i += 1;
            result.push(bytes[i] as char);
        } else {
            result.push(b as char);
        }
        i += 1;
    }

    (result, i)
}
