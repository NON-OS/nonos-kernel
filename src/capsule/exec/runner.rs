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

extern crate alloc;
use alloc::vec::Vec;
use crate::capsule::{CapsuleId, UnlockToken, download, registry};
use super::bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError { DownloadFailed, LoadFailed, SpawnFailed }

pub fn run_from_ipfs(cid: &str, token: UnlockToken) -> Result<(CapsuleId, u64), RunError> {
    let id = download::download_and_load(cid, token).map_err(|_| RunError::DownloadFailed)?;
    let pid = bridge::spawn_capsule(id).map_err(|_| RunError::SpawnFailed)?;
    Ok((id, pid))
}

pub fn run_from_data(data: &[u8], token: UnlockToken) -> Result<(CapsuleId, u64), RunError> {
    let id = crate::capsule::load(data, token).map_err(|_| RunError::LoadFailed)?;
    let pid = bridge::spawn_capsule(id).map_err(|_| RunError::SpawnFailed)?;
    Ok((id, pid))
}

pub fn run_cached(cid: &str, token: UnlockToken) -> Result<(CapsuleId, u64), RunError> {
    let data = download::cache::get(cid).ok_or(RunError::DownloadFailed)?;
    run_from_data(&data, token)
}

pub fn stop(id: CapsuleId) -> Result<(), RunError> {
    bridge::terminate_capsule(id, 0).map_err(|_| RunError::SpawnFailed)
}

pub fn force_stop(id: CapsuleId) {
    let _ = bridge::terminate_capsule(id, -1);
    registry::remove(id);
}

pub fn running_count() -> usize {
    registry::count()
}

pub fn list_running() -> Vec<CapsuleId> {
    registry::get_all_ids()
}
