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

//! A device that does not advertise an INTx pin (irq_pin == 0)
//! must keep returning `NotIntx` from the legacy bind path even
//! after MSI-X support landed. Capsules opt into MSI-X by setting
//! the flag explicitly; nothing routes silently.

use alloc::vec;

use crate::broker::claim;
use crate::broker::device::DeviceRecord;
use crate::broker::irq::bind::bind;
use crate::broker::irq::types::IrqBindError;
use crate::broker::table;
use crate::fixtures::reset::reset_all;

use super::intx_setup::{intx_request, record, DEVICE_ID, PID};
use super::lock::TEST_LOCK;

#[test]
fn msix_only_device_still_returns_not_intx() {
    let _g = TEST_LOCK.lock();
    reset_all();
    let mut rec: DeviceRecord = record();
    rec.irq_pin = 0;
    rec.irq_line = 0xFF;
    table::install_for_test(vec![rec]);
    let epoch = claim::install_for_test(PID, DEVICE_ID);
    let err = bind(PID, intx_request(epoch)).unwrap_err();
    assert_eq!(err, IrqBindError::NotIntx);
}
