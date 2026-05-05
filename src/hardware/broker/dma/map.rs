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

//! `MkDmaMap` core: validate ownership, allocate a physical frame,
//! zero it, map it into the caller's user address space with
//! NX / R+W / cacheable / user attributes, and record the grant.
//!
//! Phase A scope: a single page per grant. Multi-page contiguous
//! grants need the frame allocator to grow a contiguous-run path
//! and are deferred. The driver capsule does several
//! single-page grants when it needs more.

use super::records;
use super::types::{DmaGrant, DmaMapError, DmaMapRequest, DmaMapResult};
use super::va;
use crate::hardware::broker::claim;
use crate::hardware::broker::table;
use crate::memory::addr::PhysAddr;
use crate::memory::frame_alloc::{allocate_frame, deallocate_frame};
use crate::memory::layout::DIRECTMAP_BASE;

const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;
const FLAGS_KNOWN: u32 = 0;
const MAX_LENGTH: u64 = PAGE_SIZE;

pub fn map_for_caller(pid: u32, req: DmaMapRequest) -> Result<DmaMapResult, DmaMapError> {
    if req.flags & !FLAGS_KNOWN != 0 {
        return Err(DmaMapError::UnsupportedFlags);
    }
    if req.length == 0 || req.length & PAGE_MASK != 0 {
        return Err(DmaMapError::BadLength);
    }
    if req.length > MAX_LENGTH {
        return Err(DmaMapError::BadLength);
    }
    let claim = claim::lookup(req.device_id).ok_or(DmaMapError::NotClaimed)?;
    if claim.pid != pid {
        return Err(DmaMapError::NotClaimed);
    }
    if claim.epoch != req.claim_epoch {
        return Err(DmaMapError::StaleEpoch);
    }
    if !table::contains(req.device_id) {
        return Err(DmaMapError::UnknownDevice);
    }

    let frame = allocate_frame().ok_or(DmaMapError::NoMemory)?;
    zero_frame(frame);
    let pages = req.length / PAGE_SIZE;
    let user_va = match va::reserve(pages) {
        Some(v) => v,
        None => {
            let _ = deallocate_frame(frame);
            return Err(DmaMapError::NoVaSpace);
        }
    };
    if crate::memory::paging::map_user_dma(user_va, frame, req.length as usize).is_err() {
        let _ = deallocate_frame(frame);
        return Err(DmaMapError::MapFailed);
    }

    let grant_id = records::allocate_id();
    records::insert(DmaGrant {
        grant_id,
        pid,
        device_id: req.device_id,
        claim_epoch: claim.epoch,
        physical_start: frame.as_u64(),
        user_va: user_va.as_u64(),
        length: req.length,
        flags: req.flags,
    });

    Ok(DmaMapResult {
        user_va: user_va.as_u64(),
        device_addr: frame.as_u64(),
        length: req.length,
        grant_id,
    })
}

// Zero a freshly-allocated frame through the kernel direct map.
// SAFETY: eK@nonos.systems — `DIRECTMAP_BASE + phys` is the
// canonical kernel mapping for this frame; the frame is owned
// exclusively by the broker between `allocate_frame` and `insert`,
// so no one else aliases this VA. The write is volatile so the
// compiler cannot elide it.
fn zero_frame(frame: PhysAddr) {
    let kva = (DIRECTMAP_BASE + frame.as_u64()) as *mut u64;
    unsafe {
        for i in 0..(PAGE_SIZE as usize / 8) {
            core::ptr::write_volatile(kva.add(i), 0);
        }
    }
}
