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

use core::fmt;

use crate::error::variants::SignError;

pub(super) fn try_fmt(e: &SignError, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    use SignError::*;
    Some(match e {
        VerifyTrustAnchorPolicy => write!(f, "verify: trust anchor policy mismatch"),
        VerifyTrustAnchorBadSig(a) => write!(f, "verify: trust anchor {} bad sig", a),
        VerifyEpochStale => write!(f, "verify: cert epoch stale"),
        VerifyCertRevoked => write!(f, "verify: cert serial revoked"),
        VerifyNonosIdRevoked => write!(f, "verify: nonos_id revoked"),
        VerifyExpired => write!(f, "verify: cert expired"),
        VerifyNotYetValid => write!(f, "verify: cert not yet valid"),
        VerifyNonosIdCertIdMismatch => write!(f, "verify: manifest nonos_id_cert_id mismatch"),
        VerifyNamespaceOutsideCert => write!(f, "verify: namespace outside cert globs"),
        VerifyCapsExceedCeiling => write!(f, "verify: caps exceed cert ceiling"),
        VerifyPublisherPolicy => write!(f, "verify: publisher policy mismatch"),
        VerifyPublisherKeyRevoked => write!(f, "verify: publisher key revoked"),
        VerifyPublisherBadSig(a) => write!(f, "verify: publisher {} bad sig", a),
        VerifyPayloadHashMismatch => write!(f, "verify: payload_hash mismatch"),
        VerifyTargetTripleMismatch => write!(f, "verify: target_triple mismatch"),
        VerifyEndpointDeclDrift => write!(f, "verify: endpoint declaration drift"),
        _ => return None,
    })
}
