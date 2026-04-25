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

use crate::network::onion::tls::crypto_provider::crypto;
use crate::network::onion::tls::keys::expand_label_len;
use crate::network::onion::tls::types::CipherSuite;
use alloc::vec;
use alloc::vec::Vec;

pub fn compute_psk_binder(
    psk: &[u8],
    suite: CipherSuite,
    transcript_hash_truncated: &[u8],
) -> Vec<u8> {
    let c = crypto();
    let hl = suite.hash_len();
    let mut early_secret = [0u8; 48];
    if hl == 48 {
        let zeros = [0u8; 48];
        c.hkdf_extract_384(&zeros[..hl], psk, &mut early_secret);
    } else {
        let z32 = [0u8; 32];
        let mut psk32 = [0u8; 32];
        let copy_len = psk.len().min(32);
        psk32[..copy_len].copy_from_slice(&psk[..copy_len]);
        let mut es32 = [0u8; 32];
        c.hkdf_extract(&z32, &psk32, &mut es32);
        early_secret[..32].copy_from_slice(&es32);
    }
    let mut empty_hash = [0u8; 48];
    if hl == 48 {
        c.sha384(&[], &mut empty_hash);
    } else {
        let mut eh32 = [0u8; 32];
        c.sha256(&[], &mut eh32);
        empty_hash[..32].copy_from_slice(&eh32);
    }
    let mut binder_key = vec![0u8; hl];
    expand_label_len(&early_secret[..hl], b"res binder", &empty_hash[..hl], &mut binder_key, hl);
    let mut finished_key = vec![0u8; hl];
    expand_label_len(&binder_key, b"finished", &[], &mut finished_key, hl);
    let mut binder = vec![0u8; hl];
    if hl == 48 {
        let mut out48 = [0u8; 48];
        c.hmac_sha384(&finished_key, transcript_hash_truncated, &mut out48);
        binder.copy_from_slice(&out48[..hl]);
    } else {
        let mut out32 = [0u8; 32];
        c.hmac_sha256(&finished_key, transcript_hash_truncated, &mut out32);
        binder.copy_from_slice(&out32[..hl]);
    }
    for byte in early_secret.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in binder_key.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in finished_key.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    binder
}
