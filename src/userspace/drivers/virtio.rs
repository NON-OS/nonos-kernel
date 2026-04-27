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

use super::framework::{DriverOp, DriverRequest, DriverResponse, DriverService};
use alloc::vec::Vec;

pub struct VirtioDriverService {
    devices: Vec<VirtioDevice>,
}

struct VirtioDevice {
    device_type: u32,
    base: u64,
}

impl VirtioDriverService {
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }

    fn probe(&mut self) {
        self.devices.clear();
    }

    fn read_virtq(&self, req: &DriverRequest) -> DriverResponse {
        if req.data.is_empty() {
            return DriverResponse::err(-1);
        }
        let dev_idx = req.data[0] as usize;
        if dev_idx >= self.devices.len() {
            return DriverResponse::err(-2);
        }
        let dev = &self.devices[dev_idx];
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&dev.device_type.to_le_bytes());
        data.extend_from_slice(&dev.base.to_le_bytes());
        DriverResponse::ok(data)
    }

    fn write_virtq(&self, req: &DriverRequest) -> DriverResponse {
        if req.data.is_empty() {
            return DriverResponse::err(-1);
        }
        let dev_idx = req.data[0] as usize;
        if dev_idx >= self.devices.len() {
            return DriverResponse::err(-2);
        }
        DriverResponse::ok(Vec::new())
    }
}

impl DriverService for VirtioDriverService {
    fn name(&self) -> &str {
        "virtio"
    }
    fn init(&mut self) -> Result<(), i32> {
        self.probe();
        Ok(())
    }
    fn handle(&mut self, req: DriverRequest) -> DriverResponse {
        match req.op {
            DriverOp::Init => {
                self.probe();
                DriverResponse::ok(Vec::new())
            }
            DriverOp::Read => self.read_virtq(&req),
            DriverOp::Write => self.write_virtq(&req),
            _ => DriverResponse::err(-1),
        }
    }
    fn shutdown(&mut self) {
        self.devices.clear();
    }
}
