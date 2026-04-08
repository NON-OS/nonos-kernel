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

use crate::capsule::CapsuleId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError { NotFound, Expired, InvalidSignature, InsufficientFunds, NetworkError }

#[derive(Debug, Clone)]
pub struct UnlockRequest {
    pub capsule_id: [u8; 32],
    pub wallet_addr: [u8; 20],
    pub requested_caps: u64,
}

#[derive(Debug, Clone)]
pub struct UnlockResponse {
    pub token: [u8; 32],
    pub capsule_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub approved_caps: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState { Valid, Expired, Revoked }

pub struct CachedToken {
    pub response: UnlockResponse,
    pub state: TokenState,
    pub created_at: u64,
}

impl UnlockRequest {
    pub fn new(capsule_id: [u8; 32], wallet: [u8; 20], caps: u64) -> Self {
        Self { capsule_id, wallet_addr: wallet, requested_caps: caps }
    }
}

impl UnlockResponse {
    pub fn is_expired(&self, now: u64) -> bool { now >= self.expires_at }
    pub fn remaining_time(&self, now: u64) -> u64 { self.expires_at.saturating_sub(now) }
}

impl CachedToken {
    pub fn new(response: UnlockResponse, now: u64) -> Self {
        Self { response, state: TokenState::Valid, created_at: now }
    }
}
