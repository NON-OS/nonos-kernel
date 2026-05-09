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
use nonos_capsule_sign::sign::sign_with;
use nonos_capsule_sign::wire::nonos_id_cert::{
    assemble as assemble_cert, encode_signed_region as encode_cert_body, NonosIdCertInputs,
    TrustAnchorSignatureInput,
};

use super::bundle::Bundle;

fn sigs_both(body: &[u8], b: &Bundle) -> Vec<TrustAnchorSignatureInput> {
    let sig_ed = sign_with(AlgId::Ed25519, &b.ta_seed_ed, body).unwrap();
    let sig_dl = sign_with(AlgId::MlDsa65, &b.ta_seed_dl, body).unwrap();
    vec![
        TrustAnchorSignatureInput { alg: AlgId::Ed25519, sig: sig_ed },
        TrustAnchorSignatureInput { alg: AlgId::MlDsa65, sig: sig_dl },
    ]
}

pub fn sign_cert(input: NonosIdCertInputs, b: &Bundle) -> Vec<u8> {
    let body = encode_cert_body(&input).unwrap();
    let sigs = sigs_both(&body, b);
    assemble_cert(&body, &sigs).unwrap()
}

pub fn sign_cert_only_ed(input: NonosIdCertInputs, b: &Bundle) -> Vec<u8> {
    let body = encode_cert_body(&input).unwrap();
    let sig_ed = sign_with(AlgId::Ed25519, &b.ta_seed_ed, &body).unwrap();
    let sigs = vec![TrustAnchorSignatureInput { alg: AlgId::Ed25519, sig: sig_ed }];
    assemble_cert(&body, &sigs).unwrap()
}

pub fn sign_cert_with_corrupted_ed(input: NonosIdCertInputs, b: &Bundle) -> Vec<u8> {
    let body = encode_cert_body(&input).unwrap();
    let mut sigs = sigs_both(&body, b);
    sigs[0].sig[0] ^= 0xff;
    assemble_cert(&body, &sigs).unwrap()
}
