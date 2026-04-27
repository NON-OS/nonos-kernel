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
use super::init;
use super::structure::AhciController;
use core::sync::atomic::Ordering;

impl AhciController {
    pub fn init(&mut self) -> Result<(), AhciError> {
        let ports_impl = init::init_hba(self)?;
        for port in 0..32 {
            if (ports_impl & (1 << port)) != 0 {
                if let Err(e) = init::init_port(
                    self,
                    &self.port_dma,
                    &self.ports,
                    &self.errors,
                    &self.port_resets,
                    &self.encryption_enabled,
                    self.command_timeout.load(Ordering::Relaxed),
                    port,
                ) {
                    crate::log::logger::log_critical(&alloc::format!(
                        "AHCI: Port {} init failed: {}",
                        port,
                        e
                    ));
                }
            }
        }
        init::enable_interrupts(self);
        Ok(())
    }
}
