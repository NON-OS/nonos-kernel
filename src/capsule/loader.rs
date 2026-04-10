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

use spin::Mutex;
use super::format::CapsuleHeader;
use super::verify::{verify, UnlockToken, VerifyError};
use super::types::{Capsule, CapsuleId, CapsuleState};
use super::sandbox::Sandbox;
use super::registry;

static NEXT_ID: Mutex<CapsuleId> = Mutex::new(1);

#[derive(Debug)]
pub enum LoadError { Verify(VerifyError), Elf, Memory, Process }

impl From<VerifyError> for LoadError {
    fn from(e: VerifyError) -> Self { Self::Verify(e) }
}

pub fn init_loader() {
    *NEXT_ID.lock() = 1;
}

pub fn load(data: &[u8], token: UnlockToken) -> Result<CapsuleId, LoadError> {
    let (_h, m) = verify(data, &token)?;
    let id = { let mut n = NEXT_ID.lock(); let i = *n; *n += 1; i };
    let cap = Capsule::new(id, m.id, token.token, m.caps);
    registry::insert(cap);
    Ok(id)
}

pub fn execute(id: CapsuleId, data: &[u8]) -> Result<u64, LoadError> {
    let h = CapsuleHeader::parse(data).map_err(|e| LoadError::Verify(e.into()))?;
    let elf = h.binary(data).ok_or(LoadError::Elf)?;

    // Load ELF binary to get entry point
    const USER_BASE: u64 = 0x400000;
    let loaded = crate::process::elf_loader::load_elf(elf, USER_BASE).map_err(|_| LoadError::Elf)?;
    let entry = loaded.entry;

    let cap = registry::get_mut(id).ok_or(LoadError::Process)?;
    let name = alloc::format!("capsule:{}", id);

    // Create process via the standard process API
    let pid = crate::process::create_process(&name, crate::process::ProcessState::Ready, crate::process::Priority::Normal)
        .map_err(|_| LoadError::Process)?;

    cap.pid = Some(pid as u64);
    cap.state = CapsuleState::Running;

    // Create sandbox with minimal configuration
    let sb = Sandbox::new_minimal(id, entry, cap.caps, 128 * 1024 * 1024);
    registry::insert_sandbox(id, sb);
    registry::map_pid(pid as u64, id);

    Ok(pid as u64)
}
