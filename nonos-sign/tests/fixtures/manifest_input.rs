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

use nonos_capsule_sign::wire::capsule_manifest::{
    CapsuleManifestInputs, EndpointInput, EndpointKind, VersionInput,
};
use nonos_capsule_sign::wire::derive::derive_nonos_id_cert_id;

use super::bundle::Bundle;

pub fn manifest_input(b: &Bundle, cert_id: [u8; 32]) -> CapsuleManifestInputs {
    CapsuleManifestInputs {
        nonos_id_cert_id: cert_id,
        namespace: "alice.demo".into(),
        version: VersionInput { major: 1, minor: 0, patch: 0 },
        target_triple: "x86_64-nonos".into(),
        payload_hash: b.payload_hash,
        required_caps: 0x01,
        optional_caps: 0x02,
        endpoints: vec![EndpointInput {
            kind: EndpointKind::Service,
            port: 80,
            name: "main".into(),
        }],
    }
}

pub fn cert_id_of(cert_bytes: &[u8]) -> [u8; 32] {
    derive_nonos_id_cert_id(cert_bytes)
}
