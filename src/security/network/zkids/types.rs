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
use alloc::{vec::Vec, string::String, collections::BTreeMap};
use crate::crypto::sig::ed25519::Ed25519Signature;

#[derive(Clone, Debug)]
pub struct ZkId {
    pub id_hash: [u8; 32],
    pub public_key: [u8; 32],
    pub capabilities: Vec<Capability>,
    pub created_at: u64,
    pub last_auth: u64,
    pub auth_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capability {
    SystemAdmin,
    ProcessManager,
    MemoryManager,
    NetworkAdmin,
    FileSystem,
    CryptoOperator,
    ModuleLoader,
    DebugAccess,
    TimeCritical,
    Custom(String),
}

#[derive(Clone)]
pub struct AuthChallenge {
    pub challenge_id: [u8; 32],
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub required_capabilities: Vec<Capability>,
}

#[derive(Clone)]
pub struct AuthResponse {
    pub challenge_id: [u8; 32],
    pub zkproof: Vec<u8>,
    pub signature: Ed25519Signature,
    pub requested_session_duration: u64,
}

#[derive(Clone)]
pub struct AuthSession {
    pub session_id: [u8; 32],
    pub zkid: ZkId,
    pub capabilities: Vec<Capability>,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity: u64,
}

pub struct ZkidsManager {
    pub registered_ids: BTreeMap<[u8; 32], ZkId>,
    pub active_sessions: BTreeMap<[u8; 32], AuthSession>,
    pub pending_challenges: BTreeMap<[u8; 32], AuthChallenge>,
    pub config: ZkidsConfig,
}

#[derive(Clone, Copy)]
pub struct ZkidsConfig {
    pub max_registered_ids: usize,
    pub session_timeout_seconds: u64,
    pub challenge_timeout_seconds: u64,
    pub require_zk_proofs: bool,
    pub enable_capability_inheritance: bool,
}

impl Default for ZkidsConfig {
    fn default() -> Self {
        Self {
            max_registered_ids: 1024,
            session_timeout_seconds: 3600,
            challenge_timeout_seconds: 300,
            require_zk_proofs: true,
            enable_capability_inheritance: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZkidsStats {
    pub registered_ids: usize,
    pub active_sessions: usize,
    pub pending_challenges: usize,
    pub total_authentications: u64,
}
