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

//! Single broker-error → user-errno map. Every PIO syscall
//! lifts a `PioError` through this function so the userland
//! status code is consistent across grant / read / write /
//! release.

use crate::hardware::broker::PioError;
use crate::syscall::microkernel::errnos::{
    ERRNO_INVAL, ERRNO_NODEV, ERRNO_NOTSUP, ERRNO_PERM, ERRNO_STALE,
};

pub(super) fn errno_for(e: PioError) -> i64 {
    match e {
        PioError::NotClaimed => ERRNO_PERM,
        PioError::StaleEpoch => ERRNO_STALE,
        PioError::UnknownDevice => ERRNO_NODEV,
        PioError::NotPioBar | PioError::UnsupportedFlags => ERRNO_NOTSUP,
        PioError::BadBarIndex
        | PioError::BadOffset
        | PioError::BadWidth
        | PioError::ZeroSize
        | PioError::PortOverflow
        | PioError::UnknownGrant => ERRNO_INVAL,
        PioError::NotHolder => ERRNO_PERM,
    }
}
