// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::format;

use crate::display::{
    log_error as panel_error, log_hash, log_hex, log_ok, log_size, log_u32, show_error_screen,
};
use crate::kernel_verify::CryptoVerifyResult;
use crate::loader::errors::LoaderError;
use crate::loader::KernelImage;

pub fn display_elf_info(elf: &[u8], crypto: &CryptoVerifyResult, gop: bool) {
    if !gop {
        return;
    }
    log_size(b"ELF len   ", elf.len());
    log_size(b"code_size ", crypto.kernel_code_size);
    if elf.len() >= 8 {
        let mut hdr = [0u8; 8];
        hdr.copy_from_slice(&elf[..8]);
        log_hash(b"ELF hdr   ", &hdr);
    }
}

pub fn display_loaded_image(image: &KernelImage, gop: bool) {
    if !gop {
        return;
    }
    log_ok(b"ELF64 parsed successfully");
    log_hex(b"entry   ", image.entry_point as u64);
    log_hex(b"base    ", image.address as u64);
    log_size(b"size    ", image.size);
    log_u32(b"segments ", image.alloc_count as u32);
}

pub fn display_load_failure(
    elf: &[u8],
    crypto: &CryptoVerifyResult,
    full: &[u8],
    gop: bool,
    e: &LoaderError,
) {
    if !gop {
        return;
    }
    log_size(b"FAIL len  ", elf.len());
    log_size(b"FAIL code ", crypto.kernel_code_size);
    log_size(b"FAIL full ", full.len());
    let err_str = format!("{}", e);
    panel_error(err_str.as_bytes());
    panel_error(b"ELF parse failed");
    show_error_screen(b"Kernel ELF parsing failed");
}
