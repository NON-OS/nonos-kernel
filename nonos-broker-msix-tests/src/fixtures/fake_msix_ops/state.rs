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

use alloc::vec::Vec;
use spin::Mutex;

use super::calls::{ProgramCall, TeardownCall};
use crate::drivers::pci::types::PciAddress;

pub struct FakeMsixOps {
    pub programs: Mutex<Vec<ProgramCall>>,
    pub teardowns: Mutex<Vec<TeardownCall>>,
    pub disables: Mutex<Vec<PciAddress>>,
    pub program_should_fail: Mutex<bool>,
}

impl FakeMsixOps {
    pub const fn new() -> Self {
        Self {
            programs: Mutex::new(Vec::new()),
            teardowns: Mutex::new(Vec::new()),
            disables: Mutex::new(Vec::new()),
            program_should_fail: Mutex::new(false),
        }
    }

    pub fn reset(&self) {
        self.programs.lock().clear();
        self.teardowns.lock().clear();
        self.disables.lock().clear();
        *self.program_should_fail.lock() = false;
    }
}
