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

use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn check(manifest: &CapsuleManifest, payload: &[u8]) -> Result<(), ManifestVerifyError> {
    let computed = *blake3::hash(payload).as_bytes();
    if computed != manifest.payload_hash {
        return Err(ManifestVerifyError::PayloadHashMismatch);
    }
    Ok(())
}
