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

use crate::error::SignError;
use crate::wire::constants::{
    MAX_KEYS_PER_ALG, MAX_METADATA_LEN, MAX_NAMESPACE_GLOBS, MAX_NAMESPACE_GLOB_LEN,
    MAX_PUBLISHER_KEYS, MAX_TRUST_ANCHOR_SIGNATURES,
};

use super::inputs::{NonosIdCertInputs, PublisherKeyInput, TrustAnchorSignatureInput};

pub(super) fn check_body(input: &NonosIdCertInputs) -> Result<(), SignError> {
    let g = &input.namespace_globs;
    if g.is_empty() || g.len() > MAX_NAMESPACE_GLOBS {
        return Err(SignError::CertNamespaceGlobCount(g.len()));
    }
    for s in g {
        let n = s.as_bytes().len();
        if n == 0 || n > MAX_NAMESPACE_GLOB_LEN {
            return Err(SignError::CertNamespaceGlobLen(n));
        }
    }
    if input.metadata.as_bytes().len() > MAX_METADATA_LEN {
        return Err(SignError::CertMetadataLen(input.metadata.as_bytes().len()));
    }
    if input.valid_from_ms == 0 || input.valid_until_ms <= input.valid_from_ms {
        return Err(SignError::CertValidWindow {
            from: input.valid_from_ms,
            until: input.valid_until_ms,
        });
    }
    let pk = &input.publisher_keys;
    if pk.is_empty() || pk.len() > MAX_PUBLISHER_KEYS {
        return Err(SignError::CertPublisherKeyCount(pk.len()));
    }
    for k in pk {
        check_pub_key(k, pk)?;
    }
    Ok(())
}

fn check_pub_key(k: &PublisherKeyInput, all: &[PublisherKeyInput]) -> Result<(), SignError> {
    if k.pubkey.len() != k.alg.pubkey_len() {
        return Err(SignError::CertPubkeyLen {
            alg: k.alg.label(),
            expected: k.alg.pubkey_len(),
            got: k.pubkey.len(),
        });
    }
    if all.iter().filter(|x| x.alg == k.alg).count() > MAX_KEYS_PER_ALG {
        return Err(SignError::CertKeysPerAlg(k.alg.label()));
    }
    Ok(())
}

pub(super) fn check_sigs(sigs: &[TrustAnchorSignatureInput]) -> Result<(), SignError> {
    if sigs.is_empty() || sigs.len() > MAX_TRUST_ANCHOR_SIGNATURES {
        return Err(SignError::CertTrustAnchorSigCount(sigs.len()));
    }
    for s in sigs {
        if s.sig.len() != s.alg.sig_len() {
            return Err(SignError::CertSigLen {
                alg: s.alg.label(),
                expected: s.alg.sig_len(),
                got: s.sig.len(),
            });
        }
    }
    Ok(())
}
