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

use crate::security::keyring_capsule::KeyringCapsuleError;

pub(super) fn err_name(e: KeyringCapsuleError) -> &'static [u8] {
    match e {
        KeyringCapsuleError::Dead => b"Dead",
        KeyringCapsuleError::Stale => b"Stale",
        KeyringCapsuleError::AccessDenied => b"AccessDenied",
        KeyringCapsuleError::NotFound => b"NotFound",
        KeyringCapsuleError::Locked => b"Locked",
        KeyringCapsuleError::Full => b"Full",
        KeyringCapsuleError::InvalidArgument => b"InvalidArgument",
        KeyringCapsuleError::NoCallerPid => b"NoCallerPid",
        KeyringCapsuleError::TransportFailure => b"TransportFailure",
        KeyringCapsuleError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
