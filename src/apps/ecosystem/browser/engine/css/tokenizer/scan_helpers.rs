pub fn skip_ws(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

pub fn skip_comment(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

pub fn peek_digit(bytes: &[u8], i: usize) -> bool {
    i < bytes.len() && bytes[i].is_ascii_digit()
}

pub fn peek_dot_digit(bytes: &[u8], i: usize) -> bool {
    i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit()
}
