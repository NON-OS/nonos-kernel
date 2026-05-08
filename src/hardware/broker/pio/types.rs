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

//! Wire-form types for `MkPioGrant`, `MkPioRead`, `MkPioWrite`,
//! `MkPioRelease`. The grant exposes a single PIO BAR window to
//! the holder; reads and writes are kernel-mediated, so userland
//! never executes `in`/`out` directly.

#[derive(Debug, Clone, Copy)]
pub struct PioGrantRequest {
    pub device_id: u64,
    pub claim_epoch: u64,
    pub bar_index: u8,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct PioGrantResult {
    pub port_base: u16,
    pub port_count: u16,
    pub grant_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PioWidth {
    U8 = 1,
    U16 = 2,
    U32 = 4,
}

impl PioWidth {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::U8),
            2 => Some(Self::U16),
            4 => Some(Self::U32),
            _ => None,
        }
    }

    pub fn bytes(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PioError {
    NotClaimed,
    StaleEpoch,
    UnknownDevice,
    BadBarIndex,
    NotPioBar,
    UnsupportedFlags,
    ZeroSize,
    PortOverflow,
    UnknownGrant,
    NotHolder,
    BadOffset,
    BadWidth,
}
