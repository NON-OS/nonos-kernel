extern crate alloc;
use alloc::vec::Vec;

pub fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let line_end = find_crlf(data, pos);
        if line_end.is_none() { break; }
        let line_end = line_end.unwrap_or(data.len());
        let hex_str = core::str::from_utf8(&data[pos..line_end]).unwrap_or("0");
        let chunk_size = usize::from_str_radix(hex_str.trim(), 16).unwrap_or(0);
        if chunk_size == 0 { break; }
        let chunk_start = line_end + 2;
        let chunk_end = (chunk_start + chunk_size).min(data.len());
        result.extend_from_slice(&data[chunk_start..chunk_end]);
        pos = chunk_end + 2;
    }
    result
}

fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < data.len() {
        if data[i] == b'\r' && data[i + 1] == b'\n' { return Some(i); }
        i += 1;
    }
    None
}

pub fn is_chunked_encoding(transfer_encoding: Option<&str>) -> bool {
    transfer_encoding.map(|te| te.to_ascii_lowercase().contains("chunked")).unwrap_or(false)
}

pub fn encode_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let hex = alloc::format!("{:x}\r\n", data.len());
    result.extend_from_slice(hex.as_bytes());
    result.extend_from_slice(data);
    result.extend_from_slice(b"\r\n0\r\n\r\n");
    result
}
