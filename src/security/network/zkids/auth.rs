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
use alloc::vec;
use alloc::vec::Vec;
use crate::crypto::{verify_plonk_proof, hash::blake3_hash};
use super::types::{ZkId, Capability, AuthChallenge, AuthResponse, AuthSession};
use super::state::get_zkids_manager;
use super::helpers::{derive_public_key, secure_random_bytes, create_proof_statement, derive_verification_key, verify_signature, current_timestamp};

pub fn init_zkids() -> Result<(), &'static str> {
    crate::log::logger::log_info!("[ZKIDS] Initializing Zero-Knowledge Identity System");
    let genesis_key = crate::crypto::generate_secure_key();
    let genesis_public = derive_public_key(&genesis_key);
    let id_hash = blake3_hash(&genesis_public);
    let genesis = ZkId {
        id_hash,
        public_key: genesis_public,
        capabilities: vec![
            Capability::SystemAdmin,
            Capability::ProcessManager,
            Capability::MemoryManager,
            Capability::NetworkAdmin,
            Capability::FileSystem,
            Capability::CryptoOperator,
            Capability::ModuleLoader,
            Capability::DebugAccess,
            Capability::TimeCritical,
        ],
        created_at: current_timestamp(),
        last_auth: 0,
        auth_count: 0,
    };
    let mut mgr = get_zkids_manager().write();
    mgr.registered_ids.insert(id_hash, genesis);
    Ok(())
}

pub fn register_zkid(public_key: [u8; 32], capabilities: Vec<Capability>) -> Result<[u8; 32], &'static str> {
    let mut mgr = get_zkids_manager().write();
    if mgr.registered_ids.len() >= mgr.config.max_registered_ids {
        return Err("Maximum number of registered IDs reached");
    }
    let id_hash = blake3_hash(&public_key);
    if mgr.registered_ids.contains_key(&id_hash) { return Err("ID already registered"); }
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

pub fn create_auth_challenge(id_hash: [u8; 32], required_caps: Vec<Capability>) -> Result<AuthChallenge, &'static str> {
    let mgr = get_zkids_manager().read();
    let zkid = mgr.registered_ids.get(&id_hash).ok_or("Unknown identity")?;
    for required_cap in &required_caps {
        if !zkid.capabilities.contains(required_cap) {
            return Err("Insufficient capabilities");
        }
    }
    drop(mgr);
    let challenge_id = secure_random_bytes();
    let nonce = secure_random_bytes();
    let challenge = AuthChallenge {
        challenge_id,
        nonce,
        timestamp: current_timestamp(),
        required_capabilities: required_caps,
    };
    let mut mgr = get_zkids_manager().write();
    mgr.pending_challenges.insert(challenge_id, challenge.clone());
    Ok(challenge)
}

pub fn authenticate_with_zkproof(id_hash: [u8; 32], response: AuthResponse) -> Result<[u8; 32], &'static str> {
    let mut mgr = get_zkids_manager().write();
    let challenge = mgr.pending_challenges.remove(&response.challenge_id).ok_or("Invalid or expired challenge")?;
    let current_time = current_timestamp();
    if current_time - challenge.timestamp > mgr.config.challenge_timeout_seconds {
        return Err("Challenge expired");
    }
    let mut zkid = mgr.registered_ids.get(&id_hash).ok_or("Unknown identity")?.clone();

    if mgr.config.require_zk_proofs {
        let proof_statement = create_proof_statement(&challenge, &zkid);
        let _verification_key = derive_verification_key(&zkid);
        let is_valid = verify_plonk_proof(&proof_statement, &response.zkproof);
        if !is_valid { return Err("Zero-knowledge proof verification failed"); }
    }

    if !verify_signature(&response.signature, &challenge.challenge_id, &zkid.public_key) {
        return Err("Invalid signature");
    }

    let session_id = secure_random_bytes();
    let session = AuthSession {
        session_id,
        zkid: zkid.clone(),
        capabilities: challenge.required_capabilities,
        created_at: current_time,
        expires_at: current_time + response.requested_session_duration.min(mgr.config.session_timeout_seconds),
        last_activity: current_time,
    };
    mgr.active_sessions.insert(session_id, session);
    zkid.last_auth = current_time;
    zkid.auth_count += 1;
    mgr.registered_ids.insert(id_hash, zkid);
    Ok(session_id)
}
