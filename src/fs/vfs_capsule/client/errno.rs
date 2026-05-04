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

use super::super::error::VfsCapsuleError;

pub(super) fn map_status(status: i32) -> VfsCapsuleError {
    match status {
        -2 => VfsCapsuleError::NotFound,
        -9 => VfsCapsuleError::BadFd,
        -13 => VfsCapsuleError::AccessDenied,
        -22 => VfsCapsuleError::InvalidArgument,
        -28 => VfsCapsuleError::Full,
        -90 => VfsCapsuleError::OversizedRequest,
        -116 => VfsCapsuleError::Stale,
        _ => VfsCapsuleError::TransportFailure,
    }
}
