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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DriverOp {
    Init = 0,
    Read = 1,
    Write = 2,
    Ioctl = 3,
    Interrupt = 4,
    Shutdown = 5,
}

#[derive(Debug, Clone)]
pub struct DriverRequest {
    pub op: DriverOp,
    pub device_id: u32,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DriverResponse {
    pub status: i32,
    pub data: Vec<u8>,
}

impl DriverResponse {
    pub fn ok(data: Vec<u8>) -> Self {
        Self { status: 0, data }
    }

    pub fn err(code: i32) -> Self {
        Self { status: code, data: Vec::new() }
    }
}

pub trait DriverService {
    fn name(&self) -> &str;
    fn init(&mut self) -> Result<(), i32>;
    fn handle(&mut self, req: DriverRequest) -> DriverResponse;
    fn shutdown(&mut self);
}
