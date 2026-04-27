extern crate alloc;
use super::dynamic_table::DynamicTable;
use super::static_table;
use alloc::string::String;
use alloc::vec::Vec;

pub fn encode_headers(headers: &[(String, String)], table: &mut DynamicTable) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in headers {
        if let Some(idx) = static_table::find_static(name, value) {
            encode_indexed(&mut buf, idx);
        } else if let Some(idx) = static_table::find_static_name(name) {
            encode_literal_indexed(&mut buf, idx, value);
            table.insert(name.clone(), value.clone());
        } else {
            encode_literal_new(&mut buf, name, value);
            table.insert(name.clone(), value.clone());
        }
    }
    buf
}

fn encode_indexed(buf: &mut Vec<u8>, index: usize) {
    encode_int(buf, index, 7, 0x80);
}

fn encode_literal_indexed(buf: &mut Vec<u8>, name_index: usize, value: &str) {
    encode_int(buf, name_index, 6, 0x40);
    encode_string(buf, value);
}

fn encode_literal_new(buf: &mut Vec<u8>, name: &str, value: &str) {
    buf.push(0x40);
    encode_string(buf, name);
    encode_string(buf, value);
}

fn encode_int(buf: &mut Vec<u8>, value: usize, prefix_bits: u8, mask: u8) {
    let max = (1 << prefix_bits) - 1;
    if value < max {
        buf.push(mask | value as u8);
    } else {
        buf.push(mask | max as u8);
        let mut remaining = value - max;
        while remaining >= 128 {
            buf.push(0x80 | (remaining & 0x7F) as u8);
            remaining >>= 7;
        }
        buf.push(remaining as u8);
    }
}

fn encode_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_int(buf, bytes.len(), 7, 0x00);
    buf.extend_from_slice(bytes);
}
