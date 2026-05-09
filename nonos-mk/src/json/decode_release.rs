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

use super::decode_enums::validation_status_str;
use super::schema::{ReleaseJson, ValidationJson};

pub(super) fn release_to_json(r: &CapsuleRelease) -> ReleaseJson {
    ReleaseJson {
        release_id: r.release_id.clone(),
        manifest_hash: hex::encode(r.manifest_hash),
        package_hash: hex::encode(r.package_hash),
        package_url: r.package_url.clone(),
        publisher_signature: hex::encode(&r.publisher_signature),
        supported_arches: r.supported_arches.clone(),
        kernel_abi_min: r.kernel_abi_min,
        required_capabilities: r.required_capabilities.clone(),
        validation: ValidationJson {
            status: validation_status_str(r.validation.status).to_string(),
            note: r.validation.note.clone(),
            validator_id: r.validation.validator_id.clone(),
            validated_at_ms: r.validation.validated_at_ms,
        },
    }
}
