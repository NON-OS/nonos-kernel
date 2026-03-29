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

pub const MSG_VERSION: u8 = 1;
pub const MAX_PAYLOAD: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ServiceOp {
    Ping = 0,
    Open = 1,
    Close = 2,
    Read = 3,
    Write = 4,
    Ioctl = 5,
    Query = 6,
    Subscribe = 7,
    Unsubscribe = 8,
}

#[derive(Debug, Clone)]
pub struct ServiceRequest {
    pub seq: u32,
    pub op: ServiceOp,
    pub flags: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServiceResponse {
    pub seq: u32,
    pub status: i32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ServiceMessage {
    Request(ServiceRequest),
    Response(ServiceResponse),
}
