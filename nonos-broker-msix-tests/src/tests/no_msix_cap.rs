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

//! Capsule asks for MSI-X on a device whose PCI capability list
//! does not advertise the MSI-X cap. The bind path must reject
//! without touching the slot allocator or the programmer.

use crate::broker::irq::bind::bind;
use crate::broker::irq::types::IrqBindError;
use crate::fixtures::fake_msix_ops::FakeMsixOps;

use super::lock::TEST_LOCK;
use super::msix_setup::{default_bars, fresh_with, msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn no_msix_cap_rejects() {
    let _g = TEST_LOCK.lock();
    let epoch = fresh_with(&FAKE, default_bars(), None);
    let err = bind(PID, msix_request(epoch, 2)).unwrap_err();
    assert_eq!(err, IrqBindError::NoMsixCap);
    assert!(FAKE.programs.lock().is_empty());
}
