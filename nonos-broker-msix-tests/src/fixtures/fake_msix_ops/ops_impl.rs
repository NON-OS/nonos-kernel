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

use super::calls::{ProgramCall, TeardownCall};
use super::state::FakeMsixOps;
use crate::broker::irq::msix_ops::MsixOps;
use crate::broker::irq::types::IrqBindError;
use crate::drivers::pci::types::{MsixInfo, PciAddress, PciBar};

impl MsixOps for FakeMsixOps {
    fn program_run(
        &self,
        address: &PciAddress,
        _msix: &MsixInfo,
        _bars: &[PciBar; 6],
        base_vector: u8,
        count: usize,
        dest_apic_id: u8,
    ) -> Result<(), IrqBindError> {
        if *self.program_should_fail.lock() {
            return Err(IrqBindError::MsixProgramFailed);
        }
        self.programs
            .lock()
            .push(ProgramCall { address: *address, base_vector, count, dest_apic_id });
        Ok(())
    }

    fn teardown_vector(
        &self,
        address: &PciAddress,
        _msix: &MsixInfo,
        _bars: &[PciBar; 6],
        device_vector: u16,
    ) {
        self.teardowns
            .lock()
            .push(TeardownCall { address: *address, device_vector });
    }

    fn disable_for_device(&self, address: &PciAddress, _msix: &MsixInfo) {
        self.disables.lock().push(*address);
    }
}
