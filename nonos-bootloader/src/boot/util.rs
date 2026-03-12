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

use uefi::prelude::*;
use uefi::table::runtime::ResetType;

use crate::log::logger::log_error;

pub const ZK_PROOF_MAGIC: [u8; 4] = [0x4E, 0xC3, 0x5A, 0x50];

pub fn mini_delay() {
    for _ in 0..8_000_000 {
        core::hint::spin_loop();
    }
}

pub fn micro_delay() {
    for _ in 0..1_500_000 {
        core::hint::spin_loop();
    }
}

/*
 * Find signature end in kernel binary
 *
 * Kernel layout: [elf_code][64-byte Ed25519 sig][optional ZK block]
 * Returns offset where signature ends (start of ZK block or EOF)
 */
pub fn find_signature_end(kernel_data: &[u8]) -> usize {
    const MIN_ZK_SIZE: usize = 272;

    if kernel_data.len() < 64 + MIN_ZK_SIZE {
        return kernel_data.len();
    }

    let search_start = kernel_data.len().saturating_sub(4096);
    for i in (search_start..kernel_data.len().saturating_sub(MIN_ZK_SIZE)).rev() {
        if kernel_data.len() - i >= 4 && &kernel_data[i..i + 4] == &ZK_PROOF_MAGIC {
            return i;
        }
    }

    kernel_data.len()
}

pub fn fatal_reset(st: &mut SystemTable<Boot>, reason: &str) -> ! {
    log_error("fatal", reason);
    let _ = st.stdout().reset(false);
    let _ = st.stdout().output_string(cstr16!("\r\n[FATAL] "));
    if let Ok(s) = uefi::CString16::try_from(reason) {
        let _ = st.stdout().output_string(&s);
    }
    let _ = st
        .stdout()
        .output_string(cstr16!("\r\nSystem will restart...\r\n"));

    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }

    st.runtime_services()
        .reset(ResetType::WARM, Status::LOAD_ERROR, Some(reason.as_bytes()))
}
