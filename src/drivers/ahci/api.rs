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

use spin::Once;

use super::controller::AhciController;
use super::error::AhciError;

static AHCI_CONTROLLER: Once<AhciController> = Once::new();

pub fn init_ahci() -> Result<(), AhciError> {
    if AHCI_CONTROLLER.is_completed() {
        return Ok(());
    }

    let ahci_device = crate::drivers::pci::find_device_by_class(0x01, 0x06)
        .ok_or(AhciError::NoControllerFound)?;

    let mut controller = AhciController::new(&ahci_device)?;
    controller.init()?;

    AHCI_CONTROLLER.call_once(|| controller);

    crate::log::logger::log_critical("AHCI subsystem initialized");
    Ok(())
}

#[inline]
pub fn get_controller() -> Option<&'static AhciController> {
    AHCI_CONTROLLER.get()
}
