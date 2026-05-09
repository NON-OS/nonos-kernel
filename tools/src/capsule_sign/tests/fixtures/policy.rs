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

use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::wire::trust_anchor_policy::{
    encode as encode_ta_policy, TrustAnchorKeyInput, TrustAnchorPolicyInput,
};

use super::bundle::Bundle;
use super::consts::{TA_EPOCH, VALID_FROM, VALID_UNTIL};

pub fn ta_policy(b: &Bundle) -> TrustAnchorPolicyInput {
    TrustAnchorPolicyInput {
        epoch: TA_EPOCH,
        keys: vec![
            TrustAnchorKeyInput {
                alg: AlgId::Ed25519,
                pubkey: b.ta_pub_ed.clone(),
                valid_from_ms: VALID_FROM,
                valid_until_ms: VALID_UNTIL,
            },
            TrustAnchorKeyInput {
                alg: AlgId::MlDsa65,
                pubkey: b.ta_pub_dl.clone(),
                valid_from_ms: VALID_FROM,
                valid_until_ms: VALID_UNTIL,
            },
        ],
        revoked_cert_serials: vec![],
        revoked_nonos_ids: vec![],
        revoked_publisher_key_ids: vec![],
        flags: 0,
    }
}

pub fn encode_policy(input: TrustAnchorPolicyInput) -> Vec<u8> {
    encode_ta_policy(&input).unwrap()
}
