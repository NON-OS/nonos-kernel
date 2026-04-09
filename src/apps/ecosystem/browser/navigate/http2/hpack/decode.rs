extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::static_table;
use super::dynamic_table::DynamicTable;

pub fn decode_headers(data: &[u8], table: &mut DynamicTable) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let byte = data[pos];
        if byte & 0x80 != 0 {
            let (index, consumed) = decode_int(data, pos, 7);
            pos += consumed;
            if let Some((name, value)) = resolve(index, table) {
                headers.push((name, value));
            }
        } else if byte & 0x40 != 0 {
            let (index, consumed) = decode_int(data, pos, 6);
            pos += consumed;
            let (name, value, consumed2) = decode_literal(data, pos, index, table);
            pos += consumed2;
            table.insert(name.clone(), value.clone());
            headers.push((name, value));
        } else {
            let (index, consumed) = decode_int(data, pos, 4);
            pos += consumed;
            let (name, value, consumed2) = decode_literal(data, pos, index, table);
            pos += consumed2;
            headers.push((name, value));
        }
    }
    headers
}

fn resolve(index: usize, table: &DynamicTable) -> Option<(String, String)> {
    if index <= 61 {
        static_table::lookup_static(index).map(|(n, v)| (String::from(n), String::from(v)))
    } else {
        table.get(index - 62).map(|(n, v)| (String::from(n), String::from(v)))
    }
}

fn decode_literal(data: &[u8], pos: usize, name_index: usize, table: &DynamicTable) -> (String, String, usize) {
    let mut offset = 0;
    let name = if name_index > 0 {
        resolve(name_index, table).map(|(n, _)| n).unwrap_or_default()
    } else {
        let (s, consumed) = decode_string(data, pos);
        offset += consumed;
        s
    };
    let (value, consumed) = decode_string(data, pos + offset);
    offset += consumed;
    (name, value, offset)
}

fn decode_int(data: &[u8], pos: usize, prefix_bits: u8) -> (usize, usize) {
    let max = (1usize << prefix_bits) - 1;
    let val = (data[pos] as usize) & max;
    if val < max { return (val, 1); }
    let mut result = val;
    let mut shift = 0u32;
    let mut i = 1;
    while pos + i < data.len() {
        let b = data[pos + i] as usize;
        result += (b & 0x7F) << shift;
        i += 1;
        if b & 0x80 == 0 { break; }
        shift += 7;
    }
    (result, i)
}

fn decode_string(data: &[u8], pos: usize) -> (String, usize) {
    if pos >= data.len() { return (String::new(), 0); }
    let huffman = data[pos] & 0x80 != 0;
    let (len, consumed) = decode_int(data, pos, 7);
    let start = pos + consumed;
    let end = (start + len).min(data.len());
    let bytes = &data[start..end];
    let s = if huffman { String::from_utf8_lossy(bytes).into_owned() } else { String::from_utf8_lossy(bytes).into_owned() };
    (s, consumed + len)
}
