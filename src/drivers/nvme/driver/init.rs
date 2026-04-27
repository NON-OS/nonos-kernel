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

use super::super::constants;
use super::super::controller::NvmeController;
use super::super::error::NvmeError;
use spin::Once;

static NVME_CONTROLLER: Once<NvmeController> = Once::new();

pub fn init_nvme() -> Result<(), NvmeError> {
    if NVME_CONTROLLER.is_completed() {
        return Ok(());
    }
    let devices = crate::drivers::pci::scan_and_collect();
    let pci_device = devices
        .into_iter()
        .find(|d| {
            d.class == constants::NVME_CLASS
                && d.subclass == constants::NVME_SUBCLASS
                && d.progif == constants::NVME_PROGIF
        })
        .ok_or(NvmeError::NoControllerFound)?;
    let mut controller = NvmeController::new(pci_device)?;
    controller.init()?;
    NVME_CONTROLLER.call_once(|| controller);
    crate::log::logger::log_critical("NVMe subsystem initialized");
    Ok(())
}

#[inline]
pub fn get_controller() -> Option<&'static NvmeController> {
    NVME_CONTROLLER.get()
}

pub fn is_initialized() -> bool {
    NVME_CONTROLLER.is_completed()
}
