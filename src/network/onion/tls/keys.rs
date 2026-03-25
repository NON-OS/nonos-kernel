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


use alloc::vec::Vec;
use crate::network::onion::OnionError;
use super::crypto_provider::crypto;
use super::types::CipherSuite;

pub(super) struct Secret {
    pub secret: [u8; 48],
    pub len: usize,
}

impl Secret {
    pub(super) fn new(len: usize) -> Self {
        Self { secret: [0u8; 48], len }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.secret[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.secret.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub(super) struct KeySchedule {
    pub early_prk: [u8; 48],
    pub handshake_prk: [u8; 48],
    pub master_prk: [u8; 48],
    pub client_hs: Secret,
    pub server_hs: Secret,
    pub client_app: Secret,
    pub server_app: Secret,
    hash_len: usize,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        for byte in self.early_prk.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.handshake_prk.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.master_prk.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl KeySchedule {
    pub(super) fn new() -> Self {
        Self {
            early_prk: [0u8; 48],
            handshake_prk: [0u8; 48],
            master_prk: [0u8; 48],
            client_hs: Secret::new(32),
            server_hs: Secret::new(32),
            client_app: Secret::new(32),
            server_app: Secret::new(32),
            hash_len: 32,
        }
    }

    pub(super) fn set_suite(&mut self, suite: CipherSuite) {
        self.hash_len = suite.hash_len();
        self.client_hs.len = self.hash_len;
        self.server_hs.len = self.hash_len;
        self.client_app.len = self.hash_len;
        self.server_app.len = self.hash_len;
    }

    pub(super) fn derive_after_sh(&mut self, shared: &[u8], th_sh: &[u8]) -> Result<(), OnionError> {
        let c = crypto();
        let hl = self.hash_len;
        let zeros = [0u8; 48];

        if hl == 48 {
            let mut empty_hash = [0u8; 48];
            c.sha384(&[], &mut empty_hash);

            let mut ep = [0u8; 48];
            c.hkdf_extract_384(&zeros[..hl], &zeros[..hl], &mut ep);
            self.early_prk = ep;

            let derived = expand_label_384(&self.early_prk[..hl], b"derived", &empty_hash[..hl], hl);

            let mut hp = [0u8; 48];
            c.hkdf_extract_384(&derived[..hl], shared, &mut hp);
            self.handshake_prk = hp;

            expand_label_into_384(&self.handshake_prk[..hl], b"c hs traffic", th_sh, &mut self.client_hs.secret[..hl]);
            expand_label_into_384(&self.handshake_prk[..hl], b"s hs traffic", th_sh, &mut self.server_hs.secret[..hl]);
        } else {
            let mut eh32 = [0u8; 32];
            c.sha256(&[], &mut eh32);

            let z32 = [0u8; 32];
            let mut ep32 = [0u8; 32];
            c.hkdf_extract(&z32, &z32, &mut ep32);
            self.early_prk[..32].copy_from_slice(&ep32);

            let derived32 = expand_label_256(&ep32, b"derived", &eh32);
            let mut shared32 = [0u8; 32];
            let copy_len = shared.len().min(32);
            shared32[..copy_len].copy_from_slice(&shared[..copy_len]);
            let mut hp32 = [0u8; 32];
            c.hkdf_extract(&derived32, &shared32, &mut hp32);
            self.handshake_prk[..32].copy_from_slice(&hp32);

            let th_len = th_sh.len().min(32);
            let mut th32 = [0u8; 32];
            th32[..th_len].copy_from_slice(&th_sh[..th_len]);
            let chs = expand_label_256(&hp32, b"c hs traffic", &th32);
            let shs = expand_label_256(&hp32, b"s hs traffic", &th32);
            self.client_hs.secret[..32].copy_from_slice(&chs);
            self.server_hs.secret[..32].copy_from_slice(&shs);
        }

        Ok(())
    }

    pub(super) fn derive_application(&mut self, th_finished: &[u8]) -> Result<(), OnionError> {
        let c = crypto();
        let hl = self.hash_len;
        let zeros = [0u8; 48];

        if hl == 48 {
            let mut empty_hash = [0u8; 48];
            c.sha384(&[], &mut empty_hash);

            let derived = expand_label_384(&self.handshake_prk[..hl], b"derived", &empty_hash[..hl], hl);
            let mut mp = [0u8; 48];
            c.hkdf_extract_384(&derived[..hl], &zeros[..hl], &mut mp);
            self.master_prk = mp;

            expand_label_into_384(&self.master_prk[..hl], b"c ap traffic", th_finished, &mut self.client_app.secret[..hl]);
            expand_label_into_384(&self.master_prk[..hl], b"s ap traffic", th_finished, &mut self.server_app.secret[..hl]);
        } else {
            let mut eh32 = [0u8; 32];
            c.sha256(&[], &mut eh32);

            let z32 = [0u8; 32];
            let mut hp32 = [0u8; 32];
            hp32.copy_from_slice(&self.handshake_prk[..32]);
            let derived32 = expand_label_256(&hp32, b"derived", &eh32);
            let mut mp32 = [0u8; 32];
            c.hkdf_extract(&derived32, &z32, &mut mp32);
            self.master_prk[..32].copy_from_slice(&mp32);

            let th_len = th_finished.len().min(32);
            let mut tf32 = [0u8; 32];
            tf32[..th_len].copy_from_slice(&th_finished[..th_len]);
            let cap = expand_label_256(&mp32, b"c ap traffic", &tf32);
            let sap = expand_label_256(&mp32, b"s ap traffic", &tf32);
            self.client_app.secret[..32].copy_from_slice(&cap);
            self.server_app.secret[..32].copy_from_slice(&sap);
        }

        Ok(())
    }
}

// --- SHA-256 expand_label (original paths) ---

fn expand_label_256(prk: &[u8; 32], label: &[u8], context: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    expand_label_len_256(prk, label, context, &mut out);
    out
}

fn expand_label_len_256(prk: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let mut full = Vec::new();
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    crypto().hkdf_expand(prk, &info, out);
}

// --- SHA-384 expand_label ---

fn expand_label_384(prk: &[u8], label: &[u8], context: &[u8], hl: usize) -> [u8; 48] {
    let mut out = [0u8; 48];
    expand_label_into_384(prk, label, context, &mut out[..hl]);
    out
}

fn expand_label_into_384(prk: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let mut full = Vec::new();
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    crypto().hkdf_expand_384(prk, &info, out);
}

// --- Public expand_label dispatchers ---

pub(super) fn expand_label(prk: &[u8], label: &[u8], context: &[u8], hash_len: usize) -> [u8; 48] {
    let mut out = [0u8; 48];
    expand_label_len(prk, label, context, &mut out[..hash_len], hash_len);
    out
}

pub(super) fn expand_label_len(prk: &[u8], label: &[u8], context: &[u8], out: &mut [u8], hash_len: usize) {
    if hash_len == 48 {
        expand_label_into_384(prk, label, context, out);
    } else {
        let mut prk32 = [0u8; 32];
        let copy_len = prk.len().min(32);
        prk32[..copy_len].copy_from_slice(&prk[..copy_len]);
        expand_label_len_256(&prk32, label, context, out);
    }
}
