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
    let (h, m) = verify(data, &token)?;
    let id = { let mut n = NEXT_ID.lock(); let i = *n; *n += 1; i };
    let cap = Capsule::new(id, m.id, token.token, m.caps);
    registry::insert(cap);
    Ok(id)
}

pub fn execute(id: CapsuleId, data: &[u8]) -> Result<u64, LoadError> {
    let h = CapsuleHeader::parse(data).map_err(|e| LoadError::Verify(e.into()))?;
    let elf = h.binary(data).ok_or(LoadError::Elf)?;
    let addr_space = crate::memory::AddressSpace::new_user().map_err(|_| LoadError::Memory)?;
    let entry = crate::elf::loader::load_elf(elf, &addr_space).map_err(|_| LoadError::Elf)?;
    let cap = registry::get_mut(id).ok_or(LoadError::Process)?;
    let name = alloc::format!("capsule:{}", id);
    let proc = crate::process::Process::new_capsule(id, &name, addr_space.handle(), entry)
        .map_err(|_| LoadError::Process)?;
    let pid = proc.pid();
    cap.pid = Some(pid);
    cap.state = CapsuleState::Running;
    let sb = Sandbox::new(id, addr_space, entry, cap.caps, 128 * 1024 * 1024);
    registry::insert_sandbox(id, sb);
    registry::map_pid(pid, id);
    Ok(pid)
}
