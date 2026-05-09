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

use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::wire::capsule_manifest::{
    CapsuleManifestInputs, EndpointInput, EndpointKind, VersionInput,
};

use super::args::Args;

pub(super) fn inputs(a: &Args, cert_id: [u8; 32], payload_hash: [u8; 32]) -> Result<CapsuleManifestInputs, SignError> {
    let endpoints = a
        .endpoints
        .iter()
        .map(|(k, p, n)| EndpointInput {
            kind: match *k { 2 => EndpointKind::Reply, _ => EndpointKind::Service },
            port: *p,
            name: n.clone(),
        })
        .collect();
    Ok(CapsuleManifestInputs {
        nonos_id_cert_id: cert_id,
        namespace: a.namespace.clone(),
        version: VersionInput { major: a.version.0, minor: a.version.1, patch: a.version.2 },
        target_triple: a.target.clone(),
        payload_hash,
        required_caps: a.required_caps,
        optional_caps: a.optional_caps,
        endpoints,
    })
}
