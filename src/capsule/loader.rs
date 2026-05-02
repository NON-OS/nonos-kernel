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

use super::format::CapsuleHeader;
use super::registry;
use super::sandbox::Sandbox;
use super::types::{Capsule, CapsuleId, CapsuleState};
use super::verify::{verify, UnlockToken, VerifyError};
use core::sync::atomic::Ordering;
use spin::Mutex;

static NEXT_ID: Mutex<CapsuleId> = Mutex::new(1);

#[derive(Debug)]
pub enum LoadError {
    Verify(VerifyError),
    Elf,
    Memory,
    Process,
}

impl From<VerifyError> for LoadError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}

pub fn init_loader() {
    *NEXT_ID.lock() = 1;
}

pub fn load(data: &[u8], token: UnlockToken) -> Result<CapsuleId, LoadError> {
    let (_h, m) = verify(data, &token)?;
    let id = {
        let mut n = NEXT_ID.lock();
        let i = *n;
        *n += 1;
        i
    };
    let cap = Capsule::new(id, m.id, token.token, m.caps);
    registry::insert(cap);
    Ok(id)
}

pub fn execute(id: CapsuleId, data: &[u8]) -> Result<u64, LoadError> {
    let h = CapsuleHeader::parse(data).map_err(|e| LoadError::Verify(e.into()))?;
    let elf = h.binary(data).ok_or(LoadError::Elf)?;

    let image = crate::elf::loader::load_elf_executable(elf).map_err(|_| LoadError::Elf)?;
    let entry = image.entry_point.as_u64();

    let cap = registry::get_mut(id).ok_or(LoadError::Process)?;
    let name = alloc::format!("capsule:{}", id);

    // Create process via the standard process API
    let pid = crate::process::create_process(
        &name,
        crate::process::ProcessState::Ready,
        crate::process::Priority::Normal,
    )
    .map_err(|_| LoadError::Process)?;

    // The manifest's capability set is attested by the developer signature
    // and bounded by the unlock token's approved_caps (checked in verify).
    // Install it directly on the PCB so the capsule begins life with exactly
    // the authority the signed manifest declares, not whatever the spawning
    // context happened to inherit.
    let installed = crate::process::with_process_mut(pid, |pcb| {
        pcb.caps_bits.store(cap.caps, Ordering::SeqCst);
        let mut caps = pcb.caps.lock();
        caps.permitted = cap.caps;
        caps.effective = cap.caps;
        caps.inheritable = cap.caps;
        caps.bounding = cap.caps;
    });
    if installed.is_none() {
        return Err(LoadError::Process);
    }

    cap.pid = Some(pid as u64);
    cap.state = CapsuleState::Running;

    // Create sandbox with minimal configuration
    let sb = Sandbox::new_minimal(id, entry, cap.caps, 128 * 1024 * 1024);
    registry::insert_sandbox(id, sb);
    registry::map_pid(pid as u64, id);

    Ok(pid as u64)
}
