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

use super::super::config::ConfigSpace;
use super::super::error::{PciError, Result};
use super::super::types::{MsiInfo, MsixInfo, PciBar, PciDevice};
use super::core::{configure_msi, disable_msi, is_msi_enabled};
use super::msix::{configure_msix_single, disable_msix, is_msix_enabled};

pub struct MsiController<'a> {
    config: &'a ConfigSpace,
    msi: Option<MsiInfo>,
    msix: Option<MsixInfo>,
    bars: &'a [PciBar; 6],
}

impl<'a> MsiController<'a> {
    pub fn new(device: &'a PciDevice, config: &'a ConfigSpace) -> Self {
        Self {
            config,
            msi: device.msi,
            msix: device.msix,
            bars: &device.bars,
        }
    }

    pub fn supports_msi(&self) -> bool {
        self.msi.is_some()
    }

    pub fn supports_msix(&self) -> bool {
        self.msix.is_some()
    }

    pub fn configure_single_vector(&self, vector: u8) -> Result<()> {
        if let Some(ref msix) = self.msix {
            configure_msix_single(self.config, msix, self.bars, vector)
        } else if let Some(ref msi) = self.msi {
            configure_msi(self.config, msi, vector)
        } else {
            Err(PciError::MsiNotSupported)
        }
    }

    pub fn disable(&self) -> Result<()> {
        if let Some(ref msix) = self.msix {
            disable_msix(self.config, msix)?;
        }
        if let Some(ref msi) = self.msi {
            disable_msi(self.config, msi)?;
        }
        Ok(())
    }

    pub fn is_enabled(&self) -> Result<bool> {
        if let Some(ref msix) = self.msix {
            if is_msix_enabled(self.config, msix)? {
                return Ok(true);
            }
        }
        if let Some(ref msi) = self.msi {
            if is_msi_enabled(self.config, msi)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn max_vectors(&self) -> u16 {
        if let Some(ref msix) = self.msix {
            return msix.vector_count();
        }
        if let Some(ref msi) = self.msi {
            return msi.max_vectors() as u16;
        }
        0
    }
}

pub fn disable_legacy_interrupt(config: &ConfigSpace) -> Result<()> {
    config.disable_interrupts()
}

pub fn enable_legacy_interrupt(config: &ConfigSpace) -> Result<()> {
    config.enable_interrupts()
}

pub fn get_interrupt_line(config: &ConfigSpace) -> Result<u8> {
    config.interrupt_line()
}

pub fn get_interrupt_pin(config: &ConfigSpace) -> Result<u8> {
    config.interrupt_pin()
}
