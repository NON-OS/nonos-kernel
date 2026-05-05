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

#[derive(Debug, Clone, Copy)]
pub struct IrqGrant {
    pub grant_id: u64,
    pub pid: u32,
    pub device_id: u64,
    pub claim_epoch: u64,
    pub irq_source: u32,
    pub vector: u8,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct IrqBindRequest {
    pub device_id: u64,
    pub claim_epoch: u64,
    pub irq_source: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct IrqBindResult {
    pub grant_id: u64,
    pub vector: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqBindError {
    NotClaimed,
    StaleEpoch,
    UnknownDevice,
    NotDeviceIrq,
    AlreadyBound,
    NoVector,
    UnsupportedFlags,
    NotIntx,
    PlatformError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqError {
    UnknownGrant,
    NotHolder,
}

#[derive(Debug, Clone, Copy)]
pub struct IrqPollResult {
    pub seq: u64,
    pub overflow: u64,
}
