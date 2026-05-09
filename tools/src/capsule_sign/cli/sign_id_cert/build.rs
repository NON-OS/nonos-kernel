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
use nonos_capsule_sign::keys::read_pub;
use nonos_capsule_sign::wire::derive::derive_publisher_key_id;
use nonos_capsule_sign::wire::nonos_id_cert::{NonosIdCertInputs, PublisherKeyInput};

use super::args::Args;

pub(super) fn inputs(a: &Args) -> Result<NonosIdCertInputs, SignError> {
    let mut publisher_keys: Vec<PublisherKeyInput> = Vec::with_capacity(a.pub_keys.len());
    for (alg, path) in &a.pub_keys {
        let mat = read_pub(path)?;
        if mat.alg != *alg {
            return Err(SignError::KeyFileShape(format!(
                "{}: declared {} but file is {}",
                path.display(),
                alg.label(),
                mat.alg.label()
            )));
        }
        let key_id = derive_publisher_key_id(mat.alg, &mat.bytes);
        publisher_keys.push(PublisherKeyInput { alg: mat.alg, key_id, pubkey: mat.bytes });
    }
    Ok(NonosIdCertInputs {
        cert_serial: a.serial,
        nonos_id: a.nonos_id,
        namespace_globs: a.ns_globs.clone(),
        allowed_caps_ceiling: a.caps_ceiling,
        metadata: a.metadata.clone(),
        valid_from_ms: a.valid_from_ms,
        valid_until_ms: a.valid_until_ms,
        trust_anchor_epoch: a.epoch,
        publisher_keys,
    })
}
