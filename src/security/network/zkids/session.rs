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
use super::types::{Capability, ZkidsStats};
use super::state::get_zkids_manager;
use super::helpers::current_timestamp;

pub fn validate_session(session_id: [u8; 32]) -> Result<Vec<Capability>, &'static str> {
    let mut mgr = get_zkids_manager().write();
    let session = mgr.active_sessions.get_mut(&session_id).ok_or("Invalid session")?;
    let current_time = current_timestamp();
    if current_time > session.expires_at {
        mgr.active_sessions.remove(&session_id);
        return Err("Session expired");
    }
    session.last_activity = current_time;
    Ok(session.capabilities.clone())
}

pub fn has_capability(session_id: [u8; 32], capability: &Capability) -> bool {
    validate_session(session_id).map_or(false, |caps| caps.contains(capability))
}

pub fn cleanup_expired() {
    let mut mgr = get_zkids_manager().write();
    let current_time = current_timestamp();
    let expired_sessions: Vec<[u8; 32]> = mgr.active_sessions.iter()
        .filter(|(_, s)| current_time > s.expires_at)
        .map(|(id, _)| *id).collect();
    for session_id in expired_sessions { mgr.active_sessions.remove(&session_id); }
    let expired_challenges: Vec<[u8; 32]> = mgr.pending_challenges.iter()
        .filter(|(_, c)| current_time - c.timestamp > mgr.config.challenge_timeout_seconds)
        .map(|(id, _)| *id).collect();
    for challenge_id in expired_challenges { mgr.pending_challenges.remove(&challenge_id); }
}

pub fn get_zkids_stats() -> ZkidsStats {
    let mgr = get_zkids_manager().read();
    ZkidsStats {
        registered_ids: mgr.registered_ids.len(),
        active_sessions: mgr.active_sessions.len(),
        pending_challenges: mgr.pending_challenges.len(),
        total_authentications: mgr.registered_ids.values().map(|zkid| zkid.auth_count).sum(),
    }
}
