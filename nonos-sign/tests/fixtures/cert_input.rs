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
use nonos_capsule_sign::wire::nonos_id_cert::{NonosIdCertInputs, PublisherKeyInput};

use super::bundle::Bundle;
use super::consts::{CERT_SERIAL, TA_EPOCH, VALID_FROM, VALID_UNTIL};

pub fn cert_input(b: &Bundle) -> NonosIdCertInputs {
    NonosIdCertInputs {
        cert_serial: CERT_SERIAL,
        nonos_id: b.nonos_id,
        namespace_globs: vec!["alice.*".into()],
        allowed_caps_ceiling: 0xff,
        metadata: "alice publisher".into(),
        valid_from_ms: VALID_FROM,
        valid_until_ms: VALID_UNTIL,
        trust_anchor_epoch: TA_EPOCH,
        publisher_keys: vec![
            PublisherKeyInput {
                alg: AlgId::Ed25519,
                key_id: b.pub_key_id_ed,
                pubkey: b.pub_pub_ed.clone(),
            },
            PublisherKeyInput {
                alg: AlgId::MlDsa65,
                key_id: b.pub_key_id_dl,
                pubkey: b.pub_pub_dl.clone(),
            },
        ],
    }
}
