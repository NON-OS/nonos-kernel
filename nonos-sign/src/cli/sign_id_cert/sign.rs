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

use std::path::PathBuf;

use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::keys::read_seed;
use nonos_capsule_sign::sign::sign_with;
use nonos_capsule_sign::wire::nonos_id_cert::TrustAnchorSignatureInput;

pub(super) fn ta_signatures(
    body: &[u8],
    ta_seeds: &[(AlgId, PathBuf)],
) -> Result<Vec<TrustAnchorSignatureInput>, SignError> {
    let mut sigs = Vec::with_capacity(ta_seeds.len());
    for (alg, path) in ta_seeds {
        let mat = read_seed(path)?;
        if mat.alg != *alg {
            return Err(SignError::KeyFileShape(format!(
                "{}: declared {} but file is {}",
                path.display(),
                alg.label(),
                mat.alg.label()
            )));
        }
        let sig = sign_with(mat.alg, &mat.bytes, body)?;
        sigs.push(TrustAnchorSignatureInput { alg: mat.alg, sig });
    }
    Ok(sigs)
}
