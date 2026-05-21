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

//! Test-mode `MsixOps` override. Production picks `RealMsixOps`
//! through `mod.rs`; this file only knows how to remember and
//! return whatever a test installed, without ever falling back to
//! real PCI primitives. A test that forgot to install ops and
//! reaches `current_ops()` gets an inert error-returning ops
//! object instead of a silent MMIO write.

use spin::Mutex;

use crate::drivers::pci::types::{MsixInfo, PciAddress, PciBar};

use super::super::types::IrqBindError;
use super::ops::MsixOps;

static OVERRIDE: Mutex<Option<&'static (dyn MsixOps + 'static)>> = Mutex::new(None);
static NO_OVERRIDE: NoOverrideMsixOps = NoOverrideMsixOps;

pub fn current_ops() -> &'static dyn MsixOps {
    match *OVERRIDE.lock() {
        Some(ops) => ops,
        None => &NO_OVERRIDE,
    }
}

pub fn install_ops_for_test(ops: &'static dyn MsixOps) {
    *OVERRIDE.lock() = Some(ops);
}

pub fn clear_ops_for_test() {
    *OVERRIDE.lock() = None;
}

struct NoOverrideMsixOps;

impl MsixOps for NoOverrideMsixOps {
    fn program_run(
        &self,
        _address: &PciAddress,
        _msix: &MsixInfo,
        _bars: &[PciBar; 6],
        _base_vector: u8,
        _count: usize,
        _dest_apic_id: u8,
    ) -> Result<(), IrqBindError> {
        Err(IrqBindError::MsixProgramFailed)
    }

    fn teardown_vector(&self, _: &PciAddress, _: &MsixInfo, _: &[PciBar; 6], _: u16) {}

    fn disable_for_device(&self, _: &PciAddress, _: &MsixInfo) {}
}
