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

//! Errors the kernel-side network-driver client surfaces. The
//! `RxQueueEmpty` arm is the rx_packet "no frame ready" verdict;
//! it is intentionally distinct from `DeviceFailure` so a caller
//! can poll without treating the empty case as an error.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverNetError {
    Dead,
    Stale,
    AccessDenied,
    InvalidArgument,
    OversizedRequest,
    DeviceFailure,
    RxQueueEmpty,
    NoCallerPid,
    TransportFailure,
    ProtocolMismatch,
}
