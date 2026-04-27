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

pub struct PciDriverService {
    devices: Vec<PciDevice>,
}

struct PciDevice {
    bus: u8,
    slot: u8,
    func: u8,
    vendor: u16,
    device: u16,
}

impl PciDriverService {
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }

    fn enumerate(&mut self) {
        self.devices.clear();
    }

    fn read_config(&self, req: &DriverRequest) -> DriverResponse {
        if req.data.len() < 3 {
            return DriverResponse::err(-1);
        }
        let (bus, slot, func) = (req.data[0], req.data[1], req.data[2]);
        for dev in &self.devices {
            if dev.bus == bus && dev.slot == slot && dev.func == func {
                let mut data = alloc::vec![0u8; 4];
                data[0..2].copy_from_slice(&dev.vendor.to_le_bytes());
                data[2..4].copy_from_slice(&dev.device.to_le_bytes());
                return DriverResponse::ok(data);
            }
        }
        DriverResponse::ok(alloc::vec![0; 4])
    }

    fn write_config(&self, _req: &DriverRequest) -> DriverResponse {
        DriverResponse::ok(Vec::new())
    }
}

impl DriverService for PciDriverService {
    fn name(&self) -> &str {
        "pci"
    }
    fn init(&mut self) -> Result<(), i32> {
        self.enumerate();
        Ok(())
    }
    fn handle(&mut self, req: DriverRequest) -> DriverResponse {
        match req.op {
            DriverOp::Init => {
                self.enumerate();
                DriverResponse::ok(Vec::new())
            }
            DriverOp::Read => self.read_config(&req),
            DriverOp::Write => self.write_config(&req),
            _ => DriverResponse::err(-1),
        }
    }
    fn shutdown(&mut self) {
        self.devices.clear();
    }
}
