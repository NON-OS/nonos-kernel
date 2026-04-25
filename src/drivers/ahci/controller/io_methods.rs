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

use super::super::error::AhciError;
use super::structure::AhciController;
use super::{io, ncq_read, ncq_write};
use core::sync::atomic::Ordering;

impl AhciController {
    pub fn read_sectors(
        &self,
        port: u32,
        lba: u64,
        count: u16,
        buffer_va: u64,
    ) -> Result<(), AhciError> {
        ncq_read::ncq_read_sectors(
            self,
            &self.ports,
            &self.port_dma,
            &self.validation_failures,
            &self.read_ops,
            &self.bytes_read,
            &self.errors,
            &self.port_resets,
            &self.encryption_enabled,
            &self.aes_cipher,
            &self.encryption_iv,
            self.command_timeout.load(Ordering::Relaxed),
            port,
            lba,
            count,
            buffer_va,
        )
    }

    pub fn write_sectors(
        &self,
        port: u32,
        lba: u64,
        count: u16,
        buffer_va: u64,
    ) -> Result<(), AhciError> {
        ncq_write::ncq_write_sectors(
            self,
            &self.ports,
            &self.port_dma,
            &self.validation_failures,
            &self.write_ops,
            &self.bytes_written,
            &self.errors,
            &self.port_resets,
            &self.encryption_enabled,
            &self.aes_cipher,
            &self.encryption_iv,
            self.command_timeout.load(Ordering::Relaxed),
            port,
            lba,
            count,
            buffer_va,
        )
    }

    pub fn trim_sectors(&self, port: u32, lba: u64, count: u32) -> Result<(), AhciError> {
        io::trim_sectors(
            self,
            &self.ports,
            &self.port_dma,
            &self.validation_failures,
            &self.trim_ops,
            &self.errors,
            &self.port_resets,
            self.command_timeout.load(Ordering::Relaxed),
            port,
            lba,
            count,
        )
    }
}
