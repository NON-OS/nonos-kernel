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

//! Core types for the NONOS daemon.

pub const NOX_DECIMALS: u8 = 18;
pub const NOX_TOTAL_SUPPLY: u64 = 800_000_000;
pub const NOX_STAKING_POOL: u64 = 32_000_000;
pub const EPOCH_DURATION_SECS: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Stopped,
    Starting,
    Running,
    Syncing,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
    Diamond,
}

impl NodeTier {
    pub fn min_stake(&self) -> u64 {
        match self {
            NodeTier::Bronze => 1_000,
            NodeTier::Silver => 10_000,
            NodeTier::Gold => 50_000,
            NodeTier::Platinum => 200_000,
            NodeTier::Diamond => 1_000_000,
        }
    }

    pub fn lock_days(&self) -> u32 {
        match self {
            NodeTier::Bronze => 0,
            NodeTier::Silver => 30,
            NodeTier::Gold => 90,
            NodeTier::Platinum => 180,
            NodeTier::Diamond => 365,
        }
    }

    pub fn apy_range(&self) -> (u8, u8) {
        match self {
            NodeTier::Bronze => (5, 8),
            NodeTier::Silver => (8, 12),
            NodeTier::Gold => (12, 18),
            NodeTier::Platinum => (18, 25),
            NodeTier::Diamond => (25, 35),
        }
    }

    pub fn multiplier(&self) -> u32 {
        match self {
            NodeTier::Bronze => 100,
            NodeTier::Silver => 150,
            NodeTier::Gold => 200,
            NodeTier::Platinum => 250,
            NodeTier::Diamond => 300,
        }
    }

    pub fn from_stake(stake: u64) -> Self {
        if stake >= 1_000_000 {
            NodeTier::Diamond
        } else if stake >= 200_000 {
            NodeTier::Platinum
        } else if stake >= 50_000 {
            NodeTier::Gold
        } else if stake >= 10_000 {
            NodeTier::Silver
        } else {
            NodeTier::Bronze
        }
    }

    pub fn name(&self) -> &'static [u8] {
        match self {
            NodeTier::Bronze => b"Bronze",
            NodeTier::Silver => b"Silver",
            NodeTier::Gold => b"Gold",
            NodeTier::Platinum => b"Platinum",
            NodeTier::Diamond => b"Diamond",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct QualityScore {
    pub uptime: u8,
    pub success_rate: u8,
    pub latency_score: u8,
    pub reliability: u8,
}

impl QualityScore {
    pub const fn new() -> Self {
        Self {
            uptime: 0,
            success_rate: 0,
            latency_score: 0,
            reliability: 0,
        }
    }

    pub const fn perfect() -> Self {
        Self {
            uptime: 100,
            success_rate: 100,
            latency_score: 100,
            reliability: 100,
        }
    }

    pub fn total(&self) -> u8 {
        let score = (self.uptime as u32 * 30
            + self.success_rate as u32 * 35
            + self.latency_score as u32 * 20
            + self.reliability as u32 * 15) / 100;
        score.min(100) as u8
    }
}

impl Default for QualityScore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TokenAmount {
    pub raw: u128,
    pub decimals: u8,
}

impl TokenAmount {
    pub const fn zero() -> Self {
        Self { raw: 0, decimals: NOX_DECIMALS }
    }

    pub const fn from_nox(whole: u64) -> Self {
        Self {
            raw: (whole as u128) * 1_000_000_000_000_000_000,
            decimals: NOX_DECIMALS,
        }
    }

    pub fn whole(&self) -> u64 {
        let divisor = 10u128.pow(self.decimals as u32);
        (self.raw / divisor) as u64
    }

    pub fn frac(&self) -> u64 {
        let divisor = 10u128.pow(self.decimals as u32);
        (self.raw % divisor) as u64
    }

    pub fn is_zero(&self) -> bool {
        self.raw == 0
    }

    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.decimals != other.decimals {
            return None;
        }
        self.raw.checked_add(other.raw).map(|raw| Self {
            raw,
            decimals: self.decimals,
        })
    }

    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self.decimals != other.decimals {
            return None;
        }
        self.raw.checked_sub(other.raw).map(|raw| Self {
            raw,
            decimals: self.decimals,
        })
    }
}

impl Default for TokenAmount {
    fn default() -> Self {
        Self::zero()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Bootstrapping,
    Connected,
    Error,
}

impl Default for ConnectionStatus {
    fn default() -> Self {
        Self::Disconnected
    }
}
