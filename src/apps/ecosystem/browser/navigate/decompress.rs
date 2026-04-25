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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn get_content_encoding(headers: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-encoding:") {
            return Some(String::from(lower[17..].trim()));
        }
    }
    None
}

pub(super) fn decompress_body(body: &[u8], encoding: Option<&str>) -> Vec<u8> {
    match encoding {
        Some("gzip") | Some("x-gzip") => decompress_gzip(body).unwrap_or_else(|| body.to_vec()),
        Some("deflate") => decompress_deflate(body).unwrap_or_else(|| body.to_vec()),
        Some("br") => {
            #[cfg(feature = "nonos-brotli")]
            {
                decompress_brotli(body).unwrap_or_else(|| body.to_vec())
            }
            #[cfg(not(feature = "nonos-brotli"))]
            {
                body.to_vec()
            }
        }
        _ => body.to_vec(),
    }
}

fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B {
        return None;
    }
    let flags = data[3];
    let mut offset: usize = 10;
    if flags & 0x04 != 0 && data.len() > offset + 2 {
        let xlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }
    if flags & 0x10 != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }
    if flags & 0x02 != 0 {
        offset += 2;
    }
    if offset >= data.len() {
        return None;
    }
    let deflate_data = &data[offset..data.len().saturating_sub(8)];
    miniz_oxide::inflate::decompress_to_vec(deflate_data).ok()
}

fn decompress_deflate(data: &[u8]) -> Option<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib(data)
        .or_else(|_| miniz_oxide::inflate::decompress_to_vec(data))
        .ok()
}

#[cfg(feature = "nonos-brotli")]
fn decompress_brotli(data: &[u8]) -> Option<Vec<u8>> {
    use brotli_decompressor::{Allocator as BrAllocator, SliceWrapper, SliceWrapperMut};
    use brotli_decompressor::{BrotliDecompressCustomIo, CustomRead, CustomWrite, HuffmanCode};

    // Heap-backed memory block for the brotli allocator
    struct HeapMem<T>(Vec<T>);
    impl<T> Default for HeapMem<T> {
        fn default() -> Self {
            Self(Vec::new())
        }
    }
    impl<T> SliceWrapper<T> for HeapMem<T> {
        fn slice(&self) -> &[T] {
            &self.0
        }
    }
    impl<T> SliceWrapperMut<T> for HeapMem<T> {
        fn slice_mut(&mut self) -> &mut [T] {
            &mut self.0
        }
    }

    // Heap-backed allocator implementing brotli's Allocator trait
    struct HeapAlloc<T: Clone + Default>(core::marker::PhantomData<T>);
    impl<T: Clone + Default> BrAllocator<T> for HeapAlloc<T> {
        type AllocatedMemory = HeapMem<T>;
        fn alloc_cell(&mut self, len: usize) -> HeapMem<T> {
            HeapMem(alloc::vec![T::default(); len])
        }
        fn free_cell(&mut self, _data: HeapMem<T>) {}
    }

    // Slice-backed reader
    struct SliceReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }
    impl<'a> CustomRead<()> for SliceReader<'a> {
        fn read(&mut self, data: &mut [u8]) -> Result<usize, ()> {
            let avail = self.buf.len() - self.pos;
            let n = data.len().min(avail);
            data[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    // Vec-backed writer
    struct VecWriter(Vec<u8>);
    impl CustomWrite<()> for VecWriter {
        fn write(&mut self, data: &[u8]) -> Result<usize, ()> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> Result<(), ()> {
            Ok(())
        }
    }

    let mut reader = SliceReader { buf: data, pos: 0 };
    let mut writer = VecWriter(Vec::new());
    let mut input_buf = [0u8; 4096];
    let mut output_buf = [0u8; 4096];

    BrotliDecompressCustomIo(
        &mut reader,
        &mut writer,
        &mut input_buf[..],
        &mut output_buf[..],
        HeapAlloc::<u8>(core::marker::PhantomData),
        HeapAlloc::<u32>(core::marker::PhantomData),
        HeapAlloc::<HuffmanCode>(core::marker::PhantomData),
        (), // EOF error sentinel
    )
    .ok()?;

    Some(writer.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_body_unknown_encoding_returns_raw() {
        let data = b"raw bytes";
        let result = decompress_body(data, Some("identity"));
        assert_eq!(result, data);
    }

    #[test]
    fn test_decompress_body_none_encoding_returns_raw() {
        let data = b"pass through";
        let result = decompress_body(data, None);
        assert_eq!(result, data);
    }

    #[test]
    fn test_get_content_encoding_parses_header() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 42\r\n";
        let enc = get_content_encoding(headers);
        assert_eq!(enc.as_deref(), Some("gzip"));
    }

    #[test]
    fn test_get_content_encoding_brotli() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n";
        let enc = get_content_encoding(headers);
        assert_eq!(enc.as_deref(), Some("br"));
    }

    #[test]
    fn test_get_content_encoding_missing_returns_none() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n";
        assert!(get_content_encoding(headers).is_none());
    }

    #[cfg(feature = "nonos-brotli")]
    #[test]
    fn test_decompress_brotli_known_payload() {
        // "Hello, NONOS!" compressed with brotli
        let compressed: &[u8] = &[
            0x0B, 0x06, 0x80, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x4E, 0x4F, 0x4E, 0x4F,
            0x53, 0x21, 0x03,
        ];
        let result = decompress_brotli(compressed);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"Hello, NONOS!");
    }

    #[cfg(feature = "nonos-brotli")]
    #[test]
    fn test_decompress_brotli_via_body() {
        let compressed: &[u8] = &[
            0x0B, 0x06, 0x80, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x4E, 0x4F, 0x4E, 0x4F,
            0x53, 0x21, 0x03,
        ];
        let result = decompress_body(compressed, Some("br"));
        assert_eq!(result, b"Hello, NONOS!");
    }

    #[cfg(feature = "nonos-brotli")]
    #[test]
    fn test_decompress_brotli_corrupt_data_fallback() {
        let corrupt = &[0xFF, 0xFE, 0xFD, 0x00, 0x01];
        let result = decompress_body(corrupt, Some("br"));
        // Corrupt data should fall back to raw bytes
        assert_eq!(result, corrupt);
    }

    #[cfg(feature = "nonos-brotli")]
    #[test]
    fn test_decompress_brotli_empty_input() {
        let empty: &[u8] = &[];
        let result = decompress_body(empty, Some("br"));
        assert_eq!(result, empty);
    }

    #[test]
    fn test_decompress_deflate_roundtrip() {
        let original = b"test deflate data";
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(original, 6);
        let result = decompress_body(&compressed, Some("deflate"));
        assert_eq!(result, original);
    }
}
