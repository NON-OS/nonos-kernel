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

use super::super::error::DriverRtl8139Error;

const E_INVAL: i32 = -22;
const E_IO: i32 = -5;
const E_AGAIN: i32 = -11;
const E_MSGSIZE: i32 = -90;

pub(super) fn lift(status: i32) -> DriverRtl8139Error {
    match status {
        E_INVAL => DriverRtl8139Error::InvalidArgument,
        E_IO => DriverRtl8139Error::DeviceFailure,
        E_AGAIN => DriverRtl8139Error::RxQueueEmpty,
        E_MSGSIZE => DriverRtl8139Error::OversizedRequest,
        _ => DriverRtl8139Error::DeviceFailure,
    }
}
