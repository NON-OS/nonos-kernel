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

use nonos_marketplace_abi::CapsuleRelease;

use crate::error::CliError;

use super::encode_validation::to_validation;
use super::hex_helpers::hex32;
use super::schema::ReleaseJson;

pub(crate) fn to_release(r: &ReleaseJson) -> Result<CapsuleRelease, CliError> {
    let publisher_signature = if r.publisher_signature.is_empty() {
        Vec::new()
    } else {
        hex::decode(&r.publisher_signature)
            .map_err(|e| CliError::Json(format!("publisher_signature: {e}")))?
    };
    Ok(CapsuleRelease {
        release_id: r.release_id.clone(),
        manifest_hash: hex32(&r.manifest_hash, "manifest_hash")?,
        package_hash: hex32(&r.package_hash, "package_hash")?,
        package_url: r.package_url.clone(),
        publisher_signature,
        supported_arches: r.supported_arches.clone(),
        kernel_abi_min: r.kernel_abi_min,
        required_capabilities: r.required_capabilities.clone(),
        validation: to_validation(&r.validation)?,
    })
}
