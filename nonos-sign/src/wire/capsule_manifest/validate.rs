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
    MAX_ENDPOINTS, MAX_ENDPOINT_NAME_LEN, MAX_NAMESPACE_LEN, MAX_PUBLISHER_SIGNATURES,
    MAX_TARGET_TRIPLE_LEN,
};

use super::inputs::{
    CapsuleManifestInputs, EndpointInput, PublisherSignatureInput,
};

pub(super) fn check_body(input: &CapsuleManifestInputs) -> Result<(), SignError> {
    let n = input.namespace.as_bytes().len();
    if n == 0 || n > MAX_NAMESPACE_LEN {
        return Err(SignError::ManifestNamespaceLen(n));
    }
    let t = input.target_triple.as_bytes().len();
    if t == 0 || t > MAX_TARGET_TRIPLE_LEN {
        return Err(SignError::ManifestTargetTripleLen(t));
    }
    if input.required_caps & input.optional_caps != 0 {
        return Err(SignError::ManifestOverlappingCaps);
    }
    if input.endpoints.len() > MAX_ENDPOINTS {
        return Err(SignError::ManifestEndpointCount(input.endpoints.len()));
    }
    for (i, e) in input.endpoints.iter().enumerate() {
        check_endpoint(e)?;
        for d in &input.endpoints[..i] {
            if d.kind as u8 == e.kind as u8 && d.name == e.name {
                return Err(SignError::ManifestDuplicateEndpoint(e.name.clone()));
            }
        }
    }
    Ok(())
}

fn check_endpoint(e: &EndpointInput) -> Result<(), SignError> {
    let n = e.name.as_bytes().len();
    if n == 0 || n > MAX_ENDPOINT_NAME_LEN {
        return Err(SignError::ManifestEndpointNameLen(n));
    }
    Ok(())
}

pub(super) fn check_sigs(sigs: &[PublisherSignatureInput]) -> Result<(), SignError> {
    if sigs.is_empty() || sigs.len() > MAX_PUBLISHER_SIGNATURES {
        return Err(SignError::ManifestPublisherSigCount(sigs.len()));
    }
    for s in sigs {
        if s.sig.len() != s.alg.sig_len() {
            return Err(SignError::ManifestSigLen {
                alg: s.alg.label(),
                expected: s.alg.sig_len(),
                got: s.sig.len(),
            });
        }
    }
    Ok(())
}
