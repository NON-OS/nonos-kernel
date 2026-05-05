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

//! Revocation paths for MMIO grants. Three entry points:
//!
//!   * `unmap_grant` — single grant, holder-pid request
//!   * `release_for_device` — every grant tied to one device
//!   * `release_all_for_pid` — every grant a pid still owns
//!
//! Each variant unmaps the user pages when the holder's CR3 is the
//! active CR3 (self-context), and skips the unmap otherwise so the
//! address-space teardown can drop the PTEs wholesale.

use crate::hardware::broker::claim::release_all_for_pid as drop_claims_for_pid;
use crate::hardware::broker::grant::{self, GrantError, MmioGrant};
use crate::memory::addr::VirtAddr;

pub fn unmap_grant(pid: u32, grant_id: u64) -> Result<(), GrantError> {
    let g = grant::remove(pid, grant_id)?;
    unmap_one(&g);
    Ok(())
}

pub fn release_for_device(pid: u32, device_id: u64) -> usize {
    let drained = grant::drain_for_device(pid, device_id);
    for g in &drained {
        unmap_one(g);
    }
    drained.len()
}

pub fn release_all_for_pid(pid: u32, unmap_pages: bool) -> usize {
    let drained = grant::drain_for_pid(pid);
    if unmap_pages {
        for g in &drained {
            unmap_one(g);
        }
    }
    let _ = drop_claims_for_pid(pid);
    drained.len()
}

fn unmap_one(g: &MmioGrant) {
    let _ = crate::memory::paging::unmap_user_mmio(VirtAddr::new(g.user_va), g.length as usize);
}
