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

use super::error::I2cError;
use super::pci::LpssController;

static CONTROLLERS: Mutex<Vec<LpssController>> = Mutex::new(Vec::new());

pub fn get_controller(index: usize) -> Option<LpssController> {
    let controllers = CONTROLLERS.lock();
    controllers.get(index).cloned()
}

pub fn controller_count() -> usize {
    CONTROLLERS.lock().len()
}

pub fn read(controller: usize, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), I2cError> {
    let ctrl = get_controller(controller).ok_or(I2cError::NoController)?;
    ctrl.read(addr, reg, buf)
}

pub fn write(controller: usize, addr: u8, reg: u8, data: &[u8]) -> Result<(), I2cError> {
    let ctrl = get_controller(controller).ok_or(I2cError::NoController)?;
    ctrl.write(addr, reg, data)
}

pub fn write_read(
    controller: usize,
    addr: u8,
    write_data: &[u8],
    read_buf: &mut [u8],
) -> Result<(), I2cError> {
    let ctrl = get_controller(controller).ok_or(I2cError::NoController)?;
    ctrl.write_read(addr, write_data, read_buf)
}
