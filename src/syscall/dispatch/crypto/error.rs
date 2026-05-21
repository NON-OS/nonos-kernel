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

use crate::security::crypto_capsule::CryptoCapsuleError;
use crate::syscall::dispatch::errno;
use crate::syscall::SyscallResult;

pub(super) enum CryptoErrorContext {
    Authenticated,
    Digest,
}

pub(super) fn map_capsule_error(
    err: CryptoCapsuleError,
    context: CryptoErrorContext,
) -> SyscallResult {
    match err {
        CryptoCapsuleError::AccessDenied => errno(13),
        CryptoCapsuleError::InvalidArgument => errno(22),
        CryptoCapsuleError::AuthFailure => match context {
            CryptoErrorContext::Authenticated => errno(74),
            CryptoErrorContext::Digest => errno(5),
        },
        CryptoCapsuleError::OversizedRequest => errno(90),
        CryptoCapsuleError::ProtocolMismatch => errno(71),
        CryptoCapsuleError::Dead => errno(19),
        CryptoCapsuleError::Stale => errno(116),
        CryptoCapsuleError::NoCallerPid | CryptoCapsuleError::TransportFailure => errno(5),
    }
}
