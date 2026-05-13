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

extern crate alloc;

use alloc::vec::Vec;

use crate::capabilities::CapabilityToken;

/// All-zero `CapabilityToken` for tests that only care about a handful
/// of fields. Use the `..zero_token()` struct-update syntax to fill in
/// the rest; new authority fields appearing in production code do not
/// require touching every test site.
pub(crate) fn zero_token() -> CapabilityToken {
    CapabilityToken {
        owner_module: 0,
        permissions: Vec::new(),
        expires_at_ms: None,
        nonce: 0,
        signature: [0u8; 64],
        token_id: 0,
        subject_capsule_id: 0,
        subject_asid: 0,
        subject_measurement: [0u8; 32],
        boot_session_nonce: [0u8; 16],
        revocation_epoch: 0,
        delegation_depth: 0,
    }
}
