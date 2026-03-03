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

use super::super::controller::DesignWareI2c;
use super::super::error::I2cError;

#[derive(Clone)]
pub struct LpssController {
    pub(super) inner: DesignWareI2c,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub device_id: u16,
    pub name: &'static str,
    pub index: usize,
}

impl LpssController {
    pub fn read(&self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), I2cError> {
        self.inner.read(addr, reg, buf)
    }

    pub fn write(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), I2cError> {
        self.inner.write(addr, reg, data)
    }

    pub fn write_read(
        &self,
        addr: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<(), I2cError> {
        self.inner.write_read(addr, write_data, read_buf)
    }

    pub fn probe(&self, addr: u8) -> bool {
        self.inner.probe(addr)
    }

    pub fn base_address(&self) -> u64 {
        self.inner.base_address()
    }
}
