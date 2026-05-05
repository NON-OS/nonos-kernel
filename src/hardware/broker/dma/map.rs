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

//! `MkDmaMap` core: validate ownership, allocate physically-
//! contiguous frames, zero them, map into the caller's user address
//! space (NX / R+W / cacheable / user), and record the grant. The
//! contiguous run is required for virtio descriptor regions which
//! the device DMA-reads in one address window. Capped at
//! `MAX_PAGES` per grant in the first slice.

use super::records;
use super::types::{DmaGrant, DmaMapError, DmaMapRequest, DmaMapResult};
use super::va;
use crate::hardware::broker::claim;
use crate::hardware::broker::table;
use crate::memory::addr::PhysAddr;
use crate::memory::layout::DIRECTMAP_BASE;
use crate::memory::phys::{alloc_contiguous, free_contiguous, AllocFlags};

const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;
const FLAGS_KNOWN: u32 = 0;
const MAX_PAGES: u64 = 16;

pub fn map_for_caller(pid: u32, req: DmaMapRequest) -> Result<DmaMapResult, DmaMapError> {
    if req.flags & !FLAGS_KNOWN != 0 {
        return Err(DmaMapError::UnsupportedFlags);
    }
    if req.length == 0 || req.length & PAGE_MASK != 0 {
        return Err(DmaMapError::BadLength);
    }
    let pages = req.length / PAGE_SIZE;
    if pages > MAX_PAGES {
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

    let phys_start = alloc_contiguous(pages as usize, AllocFlags::DMA | AllocFlags::ZERO)
        .ok_or(DmaMapError::NoMemory)?;
    // The phys allocator's `ZERO` flag is best-effort across zones;
    // re-scrub through the direct map so the buffer is provably
    // zero before it leaves the kernel.
    zero_run(phys_start, req.length);

    let user_va = match va::reserve(pages) {
        Some(v) => v,
        None => {
            let _ = free_contiguous(phys_start, pages as usize);
            return Err(DmaMapError::NoVaSpace);
        }
    };
    if crate::memory::paging::map_user_dma(user_va, PhysAddr::new(phys_start), req.length as usize)
        .is_err()
    {
        let _ = free_contiguous(phys_start, pages as usize);
        return Err(DmaMapError::MapFailed);
    }

    let grant_id = records::allocate_id();
    records::insert(DmaGrant {
        grant_id,
        pid,
        device_id: req.device_id,
        claim_epoch: claim.epoch,
        physical_start: phys_start,
        user_va: user_va.as_u64(),
        length: req.length,
        flags: req.flags,
    });

    Ok(DmaMapResult {
        user_va: user_va.as_u64(),
        device_addr: phys_start,
        length: req.length,
        grant_id,
    })
}

// Zero a freshly-allocated contiguous run through the direct map.
// SAFETY: eK@nonos.systems — `DIRECTMAP_BASE + phys` is the
// canonical kernel mapping for the frames; the run is owned
// exclusively by the broker between `alloc_contiguous` and
// `records::insert`, so no other path aliases the VA. The writes
// are volatile so the compiler cannot elide them.
fn zero_run(physical_start: u64, length: u64) {
    let kva = (DIRECTMAP_BASE + physical_start) as *mut u64;
    let words = (length / 8) as usize;
    unsafe {
        for i in 0..words {
            core::ptr::write_volatile(kva.add(i), 0);
        }
    }
}
