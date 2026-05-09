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
use nonos_capsule_sign::verify::decode::{
    decode_cert, decode_manifest, decode_trust_anchor_policy,
};
use nonos_capsule_sign::verify::verify_manifest;

use crate::fixtures::{
    cert_id_of, cert_input, encode_policy, make_bundle, manifest_input, sign_cert,
    sign_manifest_full, ta_policy, REQUIRED_ALGS,
};

#[test]
fn manifest_namespace_outside_cert() {
    let b = make_bundle();
    let policy_bytes = encode_policy(ta_policy(&b));
    let cert_bytes = sign_cert(cert_input(&b), &b);
    let cert_id = cert_id_of(&cert_bytes);
    let mut m = manifest_input(&b, cert_id);
    m.namespace = "intruder.demo".into();
    let manifest_bytes = sign_manifest_full(m, &b);
    let dpolicy = decode_trust_anchor_policy(&policy_bytes).unwrap();
    let dcert = decode_cert(&cert_bytes).unwrap();
    let dmf = decode_manifest(&manifest_bytes).unwrap();
    let r = verify_manifest(&dmf, &manifest_bytes, &dcert, &cert_bytes, &dpolicy, REQUIRED_ALGS);
    assert!(matches!(r, Err(SignError::VerifyNamespaceOutsideCert)), "got {:?}", r);
}
