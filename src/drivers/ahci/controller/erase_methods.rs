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
use super::secure_erase;
use super::structure::AhciController;
use core::sync::atomic::Ordering;

impl AhciController {
    pub fn secure_erase_device(&self, port: u32, enhanced: bool) -> Result<(), AhciError> {
        secure_erase::secure_erase_device(
            self,
            &self.ports,
            &self.port_dma,
            &self.errors,
            &self.port_resets,
            &self.command_timeout,
            port,
            enhanced,
        )
    }

    pub fn verify_erasure(&self, port: u32, sample_count: u32) -> Result<bool, AhciError> {
        secure_erase::verify_erasure(
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
            sample_count,
        )
    }
}
