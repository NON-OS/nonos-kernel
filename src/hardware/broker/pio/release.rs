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

//! Revocation paths for PIO grants. Three entry points mirror the
//! MMIO shape: `release_grant` (single, holder-pid request),
//! `release_for_device` (every grant tied to one device),
//! `release_all_for_pid` (capsule exit). Removing a grant blocks
//! every subsequent `MkPioRead` / `MkPioWrite` against its id;
//! the kernel never holds physical port state on behalf of the
//! grant, so there is nothing else to undo.

use super::grant::{self, PioGrant};
use super::types::PioError;

pub fn release_grant(pid: u32, grant_id: u64) -> Result<(), PioError> {
    let _ = grant::remove(pid, grant_id)?;
    Ok(())
}

pub fn release_for_device(pid: u32, device_id: u64) -> usize {
    grant::drain_for_device(pid, device_id).len()
}

pub fn release_all_for_pid(pid: u32) -> usize {
    let drained: alloc::vec::Vec<PioGrant> = grant::drain_for_pid(pid);
    drained.len()
}
