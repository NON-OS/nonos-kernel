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

use super::constants::{PTE_NX, PTE_RW};

// ELF program-header flag bits, mirrored locally to avoid a cross-
// crate import for what is a single-byte mask.
pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
#[allow(dead_code)]
pub const PF_R: u32 = 1 << 2;

// Translate ELF segment flags into x86_64 page-table flags. Enforces
// W^X: a segment that requests both write and execute is rejected.
// `PTE_P` is added by the leaf writer; the value returned here is
// the permission overlay only.
pub fn pte_flags_from_pf(pf: u32) -> Result<u64, &'static str> {
    let writable = pf & PF_W != 0;
    let executable = pf & PF_X != 0;
    if writable && executable {
        return Err("seg_flags: W+X segment rejected");
    }
    let mut flags = 0u64;
    if writable {
        flags |= PTE_RW;
    }
    if !executable {
        flags |= PTE_NX;
    }
    Ok(flags)
}
