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

//! MSI-X declares its table BAR is index 0, but the device's BAR
//! 0 is `NotPresent`. The validator must reject before the
//! programmer is invoked, otherwise the kernel would dereference
//! a phantom MMIO region.

use crate::broker::irq::bind::bind;
use crate::broker::irq::types::IrqBindError;
use crate::drivers::pci::types::PciBar;
use crate::fixtures::device::good_msix_info;
use crate::fixtures::fake_msix_ops::FakeMsixOps;

use super::lock::TEST_LOCK;
use super::msix_setup::{fresh_with, msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn missing_table_bar_rejects() {
    let _g = TEST_LOCK.lock();
    let bars = [PciBar::NotPresent; 6];
    let epoch = fresh_with(&FAKE, bars, Some(good_msix_info()));
    let err = bind(PID, msix_request(epoch, 2)).unwrap_err();
    assert_eq!(err, IrqBindError::BadMsixBar);
    assert!(FAKE.programs.lock().is_empty());
}
