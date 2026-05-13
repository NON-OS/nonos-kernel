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

use crate::hardware::broker::MmioMapError;
use crate::syscall::microkernel::errnos::{
    ERRNO_INVAL, ERRNO_NODEV, ERRNO_NOMEM, ERRNO_NOTSUP, ERRNO_PERM, ERRNO_STALE,
};

pub(super) fn errno_for(e: MmioMapError) -> i64 {
    match e {
        MmioMapError::NotClaimed => ERRNO_PERM,
        MmioMapError::StaleEpoch => ERRNO_STALE,
        MmioMapError::UnknownDevice => ERRNO_NODEV,
        MmioMapError::BadBarIndex
        | MmioMapError::NotMmioBar
        | MmioMapError::BadAlignment
        | MmioMapError::BadRange
        | MmioMapError::ZeroLength
        | MmioMapError::Overflow => ERRNO_INVAL,
        MmioMapError::WouldExposeMsixTable | MmioMapError::WouldExposePba => ERRNO_PERM,
        MmioMapError::UnsupportedFlags => ERRNO_NOTSUP,
        MmioMapError::NoVaSpace | MmioMapError::MapFailed => ERRNO_NOMEM,
    }
}
