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

use nonos_capsule_sign::algs::ed25519::Ed25519;
use nonos_capsule_sign::algs::mldsa65::MlDsa65;
use nonos_capsule_sign::algs::traits::{KeyPair, Signer};
use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::wire::derive::{derive_nonos_id, derive_publisher_key_id};

pub struct Bundle {
    pub ta_seed_ed: Vec<u8>,
    pub ta_seed_dl: Vec<u8>,
    pub ta_pub_ed: Vec<u8>,
    pub ta_pub_dl: Vec<u8>,
    pub pub_seed_ed: Vec<u8>,
    pub pub_seed_dl: Vec<u8>,
    pub pub_pub_ed: Vec<u8>,
    pub pub_pub_dl: Vec<u8>,
    pub pub_key_id_ed: [u8; 16],
    pub pub_key_id_dl: [u8; 16],
    pub nonos_id: [u8; 32],
    pub payload_hash: [u8; 32],
}

pub fn make_bundle() -> Bundle {
    let ta_ed: KeyPair = Ed25519::keygen_random().unwrap();
    let ta_dl: KeyPair = MlDsa65::keygen_random().unwrap();
    let pub_ed: KeyPair = Ed25519::keygen_random().unwrap();
    let pub_dl: KeyPair = MlDsa65::keygen_random().unwrap();
    let pub_key_id_ed = derive_publisher_key_id(AlgId::Ed25519, &pub_ed.pubkey);
    let pub_key_id_dl = derive_publisher_key_id(AlgId::MlDsa65, &pub_dl.pubkey);
    let nonos_id = derive_nonos_id(b"alice", b"nonos.systems", b"recovery1").unwrap();
    let payload_hash = *blake3::hash(b"FAKE_ELF_PAYLOAD").as_bytes();
    Bundle {
        ta_seed_ed: ta_ed.seed,
        ta_seed_dl: ta_dl.seed,
        ta_pub_ed: ta_ed.pubkey,
        ta_pub_dl: ta_dl.pubkey,
        pub_seed_ed: pub_ed.seed,
        pub_seed_dl: pub_dl.seed,
        pub_pub_ed: pub_ed.pubkey,
        pub_pub_dl: pub_dl.pubkey,
        pub_key_id_ed,
        pub_key_id_dl,
        nonos_id,
        payload_hash,
    }
}
