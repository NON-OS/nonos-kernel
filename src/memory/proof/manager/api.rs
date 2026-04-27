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

use super::super::types::*;
use super::state::PROOF_SYSTEM;
use crate::memory::layout;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::PhysAddr;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let text_start = layout::KTEXT_BASE;
    let text_end = layout::KTEXT_BASE + layout::KTEXT_SIZE;
    let data_start = layout::KDATA_BASE;
    let data_end = layout::KDATA_BASE + layout::KDATA_SIZE;
    let heap_start = layout::KHEAP_BASE;
    let heap_end = layout::KHEAP_BASE + layout::KHEAP_SIZE;

    let text_capsule = PROOF_SYSTEM.create_capsule(
        PhysAddr::new(text_start),
        PhysAddr::new(text_end),
        CapTag::KERNEL,
        CapsulePermissions { read: true, write: false, execute: true, sealed: false },
    )?;
    PROOF_SYSTEM.seal_capsule(text_capsule)?;

    let _data_capsule = PROOF_SYSTEM.create_capsule(
        PhysAddr::new(data_start),
        PhysAddr::new(data_end),
        CapTag::KERNEL,
        CapsulePermissions { read: true, write: true, execute: false, sealed: false },
    )?;

    let _heap_capsule = PROOF_SYSTEM.create_capsule(
        PhysAddr::new(heap_start),
        PhysAddr::new(heap_end),
        CapTag::KERNEL,
        CapsulePermissions { read: true, write: true, execute: false, sealed: false },
    )?;

    PROOF_SYSTEM.create_proof(text_start, layout::KTEXT_SIZE, CapTag::KERNEL);

    crate::log_info!("[PROOF] Memory proof system initialized with 3 capsules");
    Ok(())
}

pub fn create_memory_capsule(
    start: PhysAddr,
    end: PhysAddr,
    tag: CapTag,
    read: bool,
    write: bool,
    execute: bool,
) -> Result<u64, &'static str> {
    let permissions = CapsulePermissions { read, write, execute, sealed: false };
    PROOF_SYSTEM.create_capsule(start, end, tag, permissions)
}

pub fn seal_memory_capsule(capsule_id: u64) -> Result<(), &'static str> {
    PROOF_SYSTEM.seal_capsule(capsule_id)
}

pub fn verify_capsule_integrity(capsule_id: u64) -> Result<bool, &'static str> {
    PROOF_SYSTEM.verify_capsule_integrity(capsule_id)
}

pub fn audit_map(base: u64, slide: u64, cpu_count: u64, _value: u64, tag: CapTag) -> u64 {
    let addr = base.wrapping_add(slide);
    let size = cpu_count.wrapping_mul(layout::PAGE_SIZE as u64);
    PROOF_SYSTEM.create_proof(addr, size, tag)
}

pub fn audit_phys_alloc(addr: u64, size: u64, tag: CapTag) -> u64 {
    PROOF_SYSTEM.create_proof(addr, size, tag)
}

pub fn create_memory_proof(addr: u64, size: u64, tag: CapTag) -> u64 {
    PROOF_SYSTEM.create_proof(addr, size, tag)
}

pub fn verify_memory_proof(proof_id: u64) -> Result<bool, &'static str> {
    PROOF_SYSTEM.verify_proof(proof_id)
}
