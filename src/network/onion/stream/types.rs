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


use alloc::string::String;

pub type StreamId = u16;

pub(super) const RELAY_PAYLOAD_SIZE: usize = 498;

pub(super) const STREAM_SENDME_WINDOW: i32 = 500;
pub(super) const STREAM_SENDME_INCREMENT: i32 = 50;

pub(super) const CIRCUIT_SENDME_WINDOW: i32 = 1000;
pub(super) const CIRCUIT_SENDME_INCREMENT: i32 = 100;

pub(super) const MAX_SEND_BUFFER_SIZE: usize = 64 * 1024;
pub(super) const MAX_RECV_BUFFER_SIZE: usize = 64 * 1024;

pub(super) const DEFAULT_STREAM_QUANTUM_CELLS: i32 = 10;

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    NewResolve,
    NewConnect,
    SentConnect,
    SentResolve,
    Open,
    ExitWait,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamEndReason {
    Misc = 1,
    ResolveFailed = 2,
    ConnectRefused = 3,
    ExitPolicy = 4,
    Destroy = 5,
    Done = 6,
    Timeout = 7,
    NoRoute = 8,
    Hibernating = 9,
    Internal = 10,
    ResourceLimit = 11,
    ConnReset = 12,
    TorProtocol = 13,
    NotDirectory = 14,
}

impl StreamEndReason {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => StreamEndReason::ResolveFailed,
            3 => StreamEndReason::ConnectRefused,
            4 => StreamEndReason::ExitPolicy,
            5 => StreamEndReason::Destroy,
            6 => StreamEndReason::Done,
            7 => StreamEndReason::Timeout,
            8 => StreamEndReason::NoRoute,
            9 => StreamEndReason::Hibernating,
            10 => StreamEndReason::Internal,
            11 => StreamEndReason::ResourceLimit,
            12 => StreamEndReason::ConnReset,
            13 => StreamEndReason::TorProtocol,
            14 => StreamEndReason::NotDirectory,
            _ => StreamEndReason::Misc,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StreamProtocol {
    TCP,
    HTTP,
    DNS,
    Directory,
    ControlPort,
    Custom(String),
}
