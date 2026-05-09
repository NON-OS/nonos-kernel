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

use std::fs;

use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::keys::read_pub;
use nonos_capsule_sign::wire::trust_anchor_policy::{
    encode, TrustAnchorKeyInput, TrustAnchorPolicyInput,
};

use super::args::parse;

pub fn run(args: &[String]) -> Result<(), SignError> {
    let a = parse(args)?;
    let mut keys: Vec<TrustAnchorKeyInput> = Vec::with_capacity(a.ta_pubs.len());
    for (alg, path) in &a.ta_pubs {
        let mat = read_pub(path)?;
        if mat.alg != *alg {
            return Err(SignError::KeyFileShape(format!(
                "{}: declared {} but file is {}",
                path.display(),
                alg.label(),
                mat.alg.label()
            )));
        }
        keys.push(TrustAnchorKeyInput {
            alg: mat.alg,
            pubkey: mat.bytes,
            valid_from_ms: a.valid_from_ms,
            valid_until_ms: a.valid_until_ms,
        });
    }
    let input = TrustAnchorPolicyInput {
        epoch: a.epoch,
        keys,
        revoked_cert_serials: vec![],
        revoked_nonos_ids: vec![],
        revoked_publisher_key_ids: vec![],
        flags: 0,
    };
    let bytes = encode(&input)?;
    fs::write(&a.out, &bytes)?;
    println!("wrote trust-anchor policy {} ({} bytes)", a.out.display(), bytes.len());
    Ok(())
}
