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
use crate::capsule::CapsuleId;
use alloc::vec::Vec;

pub const MAX_MSG_SIZE: usize = 64 * 1024;
pub const MAX_QUEUE_SIZE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgError {
    QueueFull,
    QueueEmpty,
    NotAllowed,
    InvalidDest,
    TooLarge,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Data,
    Request,
    Response,
    Event,
    Control,
}

#[derive(Debug, Clone)]
pub struct CapsuleMsg {
    pub id: u64,
    pub src: CapsuleId,
    pub dst: CapsuleId,
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePolicy {
    Allow,
    Deny,
    RequireCap(u64),
}

impl CapsuleMsg {
    pub fn new(id: u64, src: CapsuleId, dst: CapsuleId, mt: MsgType, payload: Vec<u8>) -> Self {
        Self { id, src, dst, msg_type: mt, payload, timestamp: crate::time::unix_timestamp() }
    }

    pub fn data(id: u64, src: CapsuleId, dst: CapsuleId, payload: Vec<u8>) -> Self {
        Self::new(id, src, dst, MsgType::Data, payload)
    }

    pub fn request(id: u64, src: CapsuleId, dst: CapsuleId, payload: Vec<u8>) -> Self {
        Self::new(id, src, dst, MsgType::Request, payload)
    }

    pub fn response(id: u64, src: CapsuleId, dst: CapsuleId, payload: Vec<u8>) -> Self {
        Self::new(id, src, dst, MsgType::Response, payload)
    }
}
