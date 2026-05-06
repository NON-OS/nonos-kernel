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

//! Errors the kernel-side client surfaces. Mirrors the entropy
//! capsule shape so call sites that already speak entropy errors
//! see a familiar surface.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverRngError {
    Dead,
    Stale,
    AccessDenied,
    OversizedRequest,
    InvalidArgument,
    DeviceFailure,
    NoCallerPid,
    TransportFailure,
    ProtocolMismatch,
}
