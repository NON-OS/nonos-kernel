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
use alloc::vec;
use super::types::{Capability, ZkId};
use super::state::get_zkids_manager;
use super::session::has_capability;
use super::helpers::current_timestamp;

pub fn export_zkid(session_id: [u8; 32], target_id: [u8; 32]) -> Result<Vec<u8>, &'static str> {
    if !has_capability(session_id, &Capability::SystemAdmin) {
        return Err("Insufficient privileges");
    }
    let mgr = get_zkids_manager().read();
    let zkid = mgr.registered_ids.get(&target_id).ok_or("ZKID not found")?;
    let mut export_data = Vec::new();
    export_data.extend_from_slice(&zkid.id_hash);
    export_data.extend_from_slice(&zkid.public_key);
    Ok(export_data)
}

pub fn import_zkid(session_id: [u8; 32], import_data: &[u8]) -> Result<[u8; 32], &'static str> {
    if !has_capability(session_id, &Capability::SystemAdmin) {
        return Err("Insufficient privileges");
    }
    if import_data.len() < 64 { return Err("Invalid import data"); }
    let mut id_hash = [0u8; 32];
    let mut public_key = [0u8; 32];
    id_hash.copy_from_slice(&import_data[0..32]);
    public_key.copy_from_slice(&import_data[32..64]);
    let capabilities = vec![Capability::FileSystem, Capability::ProcessManager];
    let mut mgr = get_zkids_manager().write();
    let zkid = ZkId {
        id_hash,
        public_key,
        capabilities,
        created_at: current_timestamp(),
        last_auth: 0,
        auth_count: 0,
    };
    mgr.registered_ids.insert(id_hash, zkid);
    Ok(id_hash)
}
