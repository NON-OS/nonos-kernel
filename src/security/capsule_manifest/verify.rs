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

use crate::crypto::asymmetric::ed25519::{self, Signature};

use super::decode::{decode, DecodeError};
use super::schema::{Manifest, MANIFEST_SCHEMA_VERSION};

const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Decode(DecodeError),
    BadSignature,
    PackageHashMismatch,
    EntryHashMismatch,
    GrantOutsideManifest,
}

impl From<DecodeError> for VerifyError {
    fn from(e: DecodeError) -> Self {
        VerifyError::Decode(e)
    }
}

pub struct VerifiedManifest {
    pub manifest: Manifest,
    pub capsule_id: [u8; 32],
}

// Verifies the manifest in `bytes` against the package and entry blob
// the loader is about to map. Returns a `VerifiedManifest` whose
// `capsule_id` is the canonical id derived from publisher key,
// package hash, namespace, and major version.
//
// `granted_caps` is the capability mask the spawn site will hand to
// the new capsule. The verifier rejects any bit not declared in
// `required_caps | optional_caps`.
pub fn verify(
    bytes: &[u8],
    package_blob: &[u8],
    entry_blob: &[u8],
    granted_caps: u64,
) -> Result<VerifiedManifest, VerifyError> {
    let manifest = decode(bytes)?;

    let signed_len = bytes.len().saturating_sub(SIGNATURE_LEN);
    if signed_len + SIGNATURE_LEN != bytes.len() {
        return Err(VerifyError::Decode(DecodeError::UnexpectedEof));
    }
    let signed_region = &bytes[..signed_len];

    let sig = Signature::from_bytes(&manifest.signature);
    if !ed25519::verify(&manifest.publisher_pubkey, signed_region, &sig) {
        return Err(VerifyError::BadSignature);
    }

    let pkg_hash = blake3_hash(package_blob);
    if pkg_hash != manifest.package_hash {
        return Err(VerifyError::PackageHashMismatch);
    }

    let entry_hash = blake3_hash(entry_blob);
    if entry_hash != manifest.entry_hash {
        return Err(VerifyError::EntryHashMismatch);
    }

    let allowed = manifest.required_caps | manifest.optional_caps;
    if granted_caps & !allowed != 0 {
        return Err(VerifyError::GrantOutsideManifest);
    }

    let capsule_id = derive_capsule_id(&manifest);
    Ok(VerifiedManifest { manifest, capsule_id })
}

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// capsule_id = BLAKE3(
//     schema_version_be (2)
//  || publisher_pubkey   (32)
//  || package_hash       (32)
//  || namespace_len_byte (1)
//  || namespace_bytes    (n)
//  || major_be           (4)
// )
fn derive_capsule_id(m: &Manifest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&MANIFEST_SCHEMA_VERSION.to_be_bytes());
    hasher.update(&m.publisher_pubkey);
    hasher.update(&m.package_hash);
    hasher.update(&[m.app_namespace_len]);
    hasher.update(&m.app_namespace[..m.app_namespace_len as usize]);
    hasher.update(&m.version.major.to_be_bytes());
    *hasher.finalize().as_bytes()
}
