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

//! Userland-status -> kernel-error mapping. The userland capsule
//! returns Linux-shape errnos in the response status field. The
//! `E_AGAIN` arm specifically maps to `RxQueueEmpty` because
//! virtio-net's rx_packet is non-blocking by contract.

use super::super::error::DriverNetError;

const E_INVAL: i32 = -22;
const E_IO: i32 = -5;
const E_AGAIN: i32 = -11;
const E_MSGSIZE: i32 = -90;

pub(super) fn lift(status: i32) -> DriverNetError {
    match status {
        E_INVAL => DriverNetError::InvalidArgument,
        E_IO => DriverNetError::DeviceFailure,
        E_AGAIN => DriverNetError::RxQueueEmpty,
        E_MSGSIZE => DriverNetError::OversizedRequest,
        _ => DriverNetError::DeviceFailure,
    }
}
