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
use nonos_capsule_sign::verify::decode::{decode_cert, decode_trust_anchor_policy};
use nonos_capsule_sign::verify::verify_cert;

use crate::fixtures::{
    cert_input, encode_policy, make_bundle, sign_cert, ta_policy, NOW_MS, REQUIRED_ALGS,
};

#[test]
fn cert_epoch_stale() {
    let b = make_bundle();
    let mut p = ta_policy(&b);
    p.epoch = 5;
    let policy_bytes = encode_policy(p);
    let mut c = cert_input(&b);
    c.trust_anchor_epoch = 1;
    let cert_bytes = sign_cert(c, &b);
    let dpolicy = decode_trust_anchor_policy(&policy_bytes).unwrap();
    let dcert = decode_cert(&cert_bytes).unwrap();
    let r = verify_cert(&dcert, &cert_bytes, &dpolicy, REQUIRED_ALGS, Some(NOW_MS));
    assert!(matches!(r, Err(SignError::VerifyEpochStale)), "got {:?}", r);
}
