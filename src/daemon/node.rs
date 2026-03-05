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

//! Node identity and management.

use super::types::{NodeStatus, NodeTier, QualityScore, TokenAmount};
use crate::crypto::{blake3_hash, get_random_bytes};

#[derive(Clone, Copy)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn generate() -> Self {
        let random = get_random_bytes();
        let hash = blake3_hash(&random);
        Self(hash)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short_id(&self) -> [u8; 20] {
        let mut short = [0u8; 20];
        short[..4].copy_from_slice(b"nxnd");
        short[4] = b'_';
        for i in 0..15 {
            let nibble = if i % 2 == 0 {
                self.0[i / 2] >> 4
            } else {
                self.0[i / 2] & 0xF
            };
            short[5 + i] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
        }
        short
    }
}

#[derive(Clone)]
pub struct NodeInfo {
    pub id: NodeId,
    pub status: NodeStatus,
    pub tier: NodeTier,
    pub quality: QualityScore,
    pub staked: TokenAmount,
    pub pending_rewards: TokenAmount,
    pub streak: u32,
    pub uptime_secs: u64,
    pub active_connections: u32,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub nickname: [u8; 32],
    pub nickname_len: usize,
}

impl NodeInfo {
    pub fn generate() -> Self {
        let id = NodeId::generate();
        let mut nickname = [0u8; 32];
        nickname[..11].copy_from_slice(b"nonos-node-");
        let short = id.short_id();
        nickname[11..19].copy_from_slice(&short[5..13]);

        Self {
            id,
            status: NodeStatus::Stopped,
            tier: NodeTier::Bronze,
            quality: QualityScore::new(),
            staked: TokenAmount::zero(),
            pending_rewards: TokenAmount::zero(),
            streak: 0,
            uptime_secs: 0,
            active_connections: 0,
            total_requests: 0,
            successful_requests: 0,
            nickname,
            nickname_len: 19,
        }
    }

    pub fn set_nickname(&mut self, name: &[u8]) {
        let len = name.len().min(32);
        self.nickname[..len].copy_from_slice(&name[..len]);
        self.nickname_len = len;
    }

    pub fn get_nickname(&self) -> &[u8] {
        &self.nickname[..self.nickname_len]
    }

    pub fn success_rate(&self) -> u8 {
        if self.total_requests == 0 {
            return 0;
        }
        ((self.successful_requests * 100) / self.total_requests) as u8
    }

    pub fn update_quality(&mut self) {
        self.quality.success_rate = self.success_rate();
        self.quality.uptime = if self.uptime_secs > 86400 { 100 } else {
            ((self.uptime_secs * 100) / 86400) as u8
        };
    }

    pub fn start(&mut self) {
        self.status = NodeStatus::Starting;
    }

    pub fn stop(&mut self) {
        self.status = NodeStatus::Stopped;
    }
}

impl Default for NodeInfo {
    fn default() -> Self {
        Self::generate()
    }
}
