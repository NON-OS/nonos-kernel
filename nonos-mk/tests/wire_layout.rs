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

//! Host-side test vectors that pin the on-wire format of the
//! marketplace index. These match what the OS-side decoder reads
//! and what the live 0xNOX endpoint serves: u32 schema_version=1
//! LE first, no NOX0 wrapper, no JSON, fixed enum discriminants,
//! signature appended after the exact `signed_bytes` range.

use ed25519_dalek::{Signer, Verifier as EdVerifier, VerifyingKey};
use nonos_marketplace_abi::{
    decode_index, encode_and_sign, encode_index, PriceKind, ValidationStatus,
};

mod fixtures;
use fixtures::{empty_index, preview_entry_index, signing_key};

#[test]
fn body_starts_with_schema_version_one_le() {
    let index = empty_index();
    let key = signing_key();
    let (blob, _sig) = encode_and_sign(index, |bytes| key.sign(bytes).to_bytes());
    assert!(blob.len() >= 4, "blob too short");
    assert_eq!(&blob[..4], &[0x01, 0x00, 0x00, 0x00], "first u32 must be schema_version=1 LE");
}

#[test]
fn no_nox0_magic_in_blob_prefix() {
    let index = empty_index();
    let key = signing_key();
    let (blob, _sig) = encode_and_sign(index, |bytes| key.sign(bytes).to_bytes());
    assert_ne!(&blob[..4], b"NOX0", "blob must not carry a NOX0 wrapper");
}

#[test]
fn signed_bytes_end_immediately_before_signature_length_prefix() {
    let mut index = empty_index();
    index.index_signature.clear();
    let pre = encode_index(&index);

    let key = signing_key();
    let (blob, sig_arr) = encode_and_sign(empty_index(), |bytes| key.sign(bytes).to_bytes());

    let signed_len = pre.signed_bytes.len();
    assert_eq!(&blob[..signed_len], pre.signed_bytes.as_slice());

    let sig_lp = u32::from_le_bytes(blob[signed_len..signed_len + 4].try_into().unwrap()) as usize;
    assert_eq!(sig_lp, 64, "signature length prefix must declare 64 bytes");
    assert_eq!(&blob[signed_len + 4..signed_len + 4 + 64], &sig_arr);
}

#[test]
fn signed_empty_index_decodes_and_verifies() {
    let key = signing_key();
    let (blob, _sig) = encode_and_sign(empty_index(), |bytes| key.sign(bytes).to_bytes());
    let decoded = decode_index(&blob).expect("decode");
    assert_eq!(decoded.index.serial, 1);
    assert_eq!(decoded.index.entries.len(), 0);

    let pubkey = VerifyingKey::from(&key);
    let sig: [u8; 64] = decoded.index.index_signature.as_slice().try_into().unwrap();
    pubkey
        .verify(decoded.signed_bytes, &ed25519_dalek::Signature::from_bytes(&sig))
        .expect("signature must verify");
}

#[test]
fn mutated_signed_byte_breaks_verification() {
    let key = signing_key();
    let (mut blob, _sig) = encode_and_sign(empty_index(), |bytes| key.sign(bytes).to_bytes());
    // Flip a byte inside the operator_pubkey raw-32 region. That
    // is structural binary, so the decoder still walks the blob,
    // but the embedded pubkey no longer matches the signed body.
    let target = 4 + 4 + "test.operator".len() + 5;
    blob[target] ^= 0xFF;
    let decoded = decode_index(&blob).expect("still decodes structurally");
    let pubkey = VerifyingKey::from(&key);
    let sig: [u8; 64] = decoded.index.index_signature.as_slice().try_into().unwrap();
    let result =
        pubkey.verify(decoded.signed_bytes, &ed25519_dalek::Signature::from_bytes(&sig));
    assert!(result.is_err(), "mutated body must not verify");
}

#[test]
fn price_kind_discriminants_pin_to_canonical_values() {
    assert_eq!(PriceKind::Free as u8, 0);
    assert_eq!(PriceKind::OneTime as u8, 1);
    assert_eq!(PriceKind::Subscription as u8, 2);
    assert_eq!(PriceKind::UsageMetered as u8, 3);
}

#[test]
fn validation_status_discriminants_pin_to_canonical_values() {
    assert_eq!(ValidationStatus::Unknown as u8, 0);
    assert_eq!(ValidationStatus::Pending as u8, 1);
    assert_eq!(ValidationStatus::Validated as u8, 2);
    assert_eq!(ValidationStatus::Rejected as u8, 3);
}

#[test]
fn preview_entry_decodes_with_pending_status_and_no_install_inputs() {
    let key = signing_key();
    let (blob, _sig) =
        encode_and_sign(preview_entry_index(), |bytes| key.sign(bytes).to_bytes());
    let decoded = decode_index(&blob).expect("decode");
    let entry = &decoded.index.entries[0];
    let release = &entry.releases[0];
    assert_eq!(release.validation.status, ValidationStatus::Pending);
    assert!(release.package_url.is_empty(), "preview must not advertise a package_url");
    assert!(release.publisher_signature.is_empty(), "preview must not carry a signature");
}

