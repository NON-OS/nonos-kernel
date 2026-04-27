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

use super::format::{CapsuleHeader, FormatError};
use super::manifest::{Manifest, ManifestError};

#[derive(Debug, Clone)]
pub struct UnlockToken {
    pub token: [u8; 32],
    pub capsule_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub approved_caps: u64,
    pub expires_at: u64,
}

#[derive(Debug)]
pub enum VerifyError {
    Format(FormatError),
    Manifest(ManifestError),
    HashMismatch,
    BadSignature,
    BadUnlock,
    CapExceeded,
    Expired,
    NoPubkey,
}

impl From<FormatError> for VerifyError {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}

impl From<ManifestError> for VerifyError {
    fn from(e: ManifestError) -> Self {
        Self::Manifest(e)
    }
}

pub fn verify(data: &[u8], token: &UnlockToken) -> Result<(CapsuleHeader, Manifest), VerifyError> {
    let h = CapsuleHeader::parse(data)?;
    let md = h.manifest(data).ok_or(VerifyError::Format(FormatError::BadOffset))?;
    let mh = crate::crypto::keccak::keccak256(md);
    if mh != token.manifest_hash {
        return Err(VerifyError::HashMismatch);
    }
    let m = Manifest::parse(md)?;
    if m.dev_pubkey == [0u8; 32] {
        return Err(VerifyError::NoPubkey);
    }
    let sig_bytes = h.signature(data).ok_or(VerifyError::Format(FormatError::BadOffset))?;
    let sd = h.signed_data(data).ok_or(VerifyError::Format(FormatError::BadOffset))?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::BadSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = crate::crypto::ed25519::Signature::from_bytes(&sig_arr);
    if !crate::crypto::ed25519::verify(&m.dev_pubkey, sd, &sig) {
        return Err(VerifyError::BadSignature);
    }
    if token.expires_at != 0 && crate::sys::clock::get_unix_time() > token.expires_at {
        return Err(VerifyError::Expired);
    }
    if token.token == [0u8; 32] {
        return Err(VerifyError::BadUnlock);
    }
    if m.caps & !token.approved_caps != 0 {
        return Err(VerifyError::CapExceeded);
    }
    Ok((h, m))
}
