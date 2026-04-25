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

pub struct NvmeDriverService {
    controllers: Vec<NvmeController>,
}

struct NvmeController {
    base: u64,
    queues: u16,
}

impl NvmeDriverService {
    pub fn new() -> Self {
        Self { controllers: Vec::new() }
    }

    fn probe(&mut self) {
        self.controllers.clear();
    }

    fn read_block(&self, req: &DriverRequest) -> DriverResponse {
        if req.data.len() < 9 {
            return DriverResponse::err(-1);
        }
        let ctrl_idx = req.data[0] as usize;
        if ctrl_idx >= self.controllers.len() {
            return DriverResponse::err(-2);
        }
        let ctrl = &self.controllers[ctrl_idx];
        if ctrl.base == 0 || ctrl.queues == 0 {
            return DriverResponse::err(-3);
        }
        DriverResponse::ok(alloc::vec![0; 512])
    }

    fn write_block(&self, req: &DriverRequest) -> DriverResponse {
        if req.data.len() < 521 {
            return DriverResponse::err(-1);
        }
        let ctrl_idx = req.data[0] as usize;
        if ctrl_idx >= self.controllers.len() {
            return DriverResponse::err(-2);
        }
        DriverResponse::ok(Vec::new())
    }
}

impl DriverService for NvmeDriverService {
    fn name(&self) -> &str {
        "nvme"
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
            DriverOp::Read => self.read_block(&req),
            DriverOp::Write => self.write_block(&req),
            _ => DriverResponse::err(-1),
        }
    }
    fn shutdown(&mut self) {
        self.controllers.clear();
    }
}
