// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType { None, Lz4, Zlib, Lzma }

pub fn compress_firmware(data: &[u8], compression_type: CompressionType) -> alloc::vec::Vec<u8> {
    match compression_type { CompressionType::None => data.to_vec(), CompressionType::Lz4 => lz4_compress(data), CompressionType::Zlib => zlib_compress(data), CompressionType::Lzma => data.to_vec() }
}

pub fn decompress_firmware(compressed_data: &[u8], compression_type: CompressionType) -> Result<alloc::vec::Vec<u8>, &'static str> {
    match compression_type { CompressionType::None => Ok(compressed_data.to_vec()), CompressionType::Lz4 => lz4_decompress(compressed_data), CompressionType::Zlib => zlib_decompress(compressed_data), CompressionType::Lzma => Ok(compressed_data.to_vec()) }
}

pub fn optimize_layout(data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut optimized = alloc::vec::Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(4096).enumerate() { if i % 2 == 0 { optimized.extend_from_slice(chunk); } }
    for (i, chunk) in data.chunks(4096).enumerate() { if i % 2 == 1 { optimized.extend_from_slice(chunk); } }
    optimized
}

fn lz4_compress(data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut compressed = alloc::vec::Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 4 < data.len() && data[i] == data[i + 1] && data[i] == data[i + 2] && data[i] == data[i + 3] {
            let run_length = count_run(&data[i..]);
            compressed.push(0x80 | core::cmp::min(run_length, 127) as u8);
            compressed.push(data[i]);
            i += run_length;
        } else { compressed.push(data[i]); i += 1; }
    }
    compressed
}

fn lz4_decompress(compressed: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let mut decompressed = alloc::vec::Vec::new();
    let mut i = 0;
    while i < compressed.len() {
        if compressed[i] & 0x80 != 0 && i + 1 < compressed.len() { let run_length = (compressed[i] & 0x7F) as usize; for _ in 0..run_length { decompressed.push(compressed[i + 1]); } i += 2; } else { decompressed.push(compressed[i]); i += 1; }
    }
    Ok(decompressed)
}

fn zlib_compress(data: &[u8]) -> alloc::vec::Vec<u8> { let mut result = alloc::vec::Vec::with_capacity(data.len() + 8); result.extend_from_slice(&[0x78, 0x9C]); result.extend_from_slice(data); let checksum = data.iter().fold(1u32, |acc, &b| acc.wrapping_add(u32::from(b))); result.extend_from_slice(&checksum.to_be_bytes()); result }
fn zlib_decompress(compressed: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> { if compressed.len() < 6 || compressed[0] != 0x78 { return Err("invalid zlib header"); } Ok(compressed[2..compressed.len() - 4].to_vec()) }
fn count_run(data: &[u8]) -> usize { if data.is_empty() { return 0; } let first = data[0]; data.iter().take_while(|&&b| b == first).count().min(127) }