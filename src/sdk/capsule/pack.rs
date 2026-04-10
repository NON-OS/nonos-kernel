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

extern crate alloc;
use alloc::vec::Vec;
use super::sign::SigningKey;
use crate::capsule::format::{NOXC_MAGIC, FORMAT_VERSION, HEADER_SIZE, SIG_SIZE};

pub fn pack_capsule(manifest: &[u8], elf: &[u8], assets: &[u8], key: &SigningKey) -> Vec<u8> {
    let manifest_off = HEADER_SIZE as u64;
    let manifest_len = manifest.len() as u64;
    let binary_off = manifest_off + manifest_len;
    let binary_len = elf.len() as u64;
    let assets_off = binary_off + binary_len;
    let assets_len = assets.len() as u64;
    let sig_off = assets_off + assets_len;
    let total = sig_off as usize + SIG_SIZE;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&NOXC_MAGIC.to_le_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&manifest_off.to_le_bytes());
    out.extend_from_slice(&manifest_len.to_le_bytes());
    out.extend_from_slice(&binary_off.to_le_bytes());
    out.extend_from_slice(&binary_len.to_le_bytes());
    out.extend_from_slice(&assets_off.to_le_bytes());
    out.extend_from_slice(&assets_len.to_le_bytes());
    out.extend_from_slice(&sig_off.to_le_bytes());
    out.extend_from_slice(manifest);
    out.extend_from_slice(elf);
    out.extend_from_slice(assets);
    let sig = key.sign(&out);
    out.extend_from_slice(&sig);
    out
}

pub fn unpack_capsule(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let h = crate::capsule::format::CapsuleHeader::parse(data).ok()?;
    let manifest = h.manifest(data)?.to_vec();
    let binary = h.binary(data)?.to_vec();
    let assets_off = h.assets_off as usize;
    let assets_len = h.assets_len as usize;
    let assets = if assets_len > 0 && assets_off + assets_len <= data.len() {
        data[assets_off..assets_off + assets_len].to_vec()
    } else { Vec::new() };
    Some((manifest, binary, assets))
}

pub fn get_manifest_hash(data: &[u8]) -> Option<[u8; 32]> {
    let h = crate::capsule::format::CapsuleHeader::parse(data).ok()?;
    let manifest = h.manifest(data)?;
    Some(crate::crypto::keccak::keccak256(manifest))
}

pub fn verify_capsule(data: &[u8]) -> bool {
    use crate::crypto::ed25519::Signature;
    let h: crate::capsule::format::CapsuleHeader = match crate::capsule::format::CapsuleHeader::parse(data) { Ok(h) => h, Err(_) => return false };
    let sig_bytes = match h.signature(data) { Some(s) => s, None => return false };
    let signed = match h.signed_data(data) { Some(d) => d, None => return false };
    let manifest = match h.manifest(data) { Some(m) => m, None => return false };
    let m = match crate::capsule::manifest::Manifest::parse(manifest) { Ok(m) => m, Err(_) => return false };
    if m.dev_pubkey == [0u8; 32] { return false; }
    if sig_bytes.len() != 64 { return false; }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    crate::crypto::ed25519::verify(&m.dev_pubkey, signed, &sig)
}
