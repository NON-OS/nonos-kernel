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

pub(super) struct Secret {
    pub secret: [u8; 32],
}

pub(super) struct KeySchedule {
    pub early_prk: [u8; 32],
    pub handshake_prk: [u8; 32],
    pub master_prk: [u8; 32],
    pub client_hs: Secret,
    pub server_hs: Secret,
    pub client_app: Secret,
    pub server_app: Secret,
}

impl KeySchedule {
    pub(super) fn new() -> Self {
        Self {
            early_prk: [0u8; 32],
            handshake_prk: [0u8; 32],
            master_prk: [0u8; 32],
            client_hs: Secret { secret: [0u8; 32] },
            server_hs: Secret { secret: [0u8; 32] },
            client_app: Secret { secret: [0u8; 32] },
            server_app: Secret { secret: [0u8; 32] },
        }
    }

    pub(super) fn derive_after_sh(&mut self, shared: &[u8; 32], th_sh: &[u8; 32]) -> Result<(), OnionError> {
        let c = crypto();
        let zeros = [0u8; 32];

        c.hkdf_extract(&zeros, &zeros, &mut self.early_prk);
        let derived = expand_label(&self.early_prk, b"derived", &[]);
        c.hkdf_extract(&derived, shared, &mut self.handshake_prk);

        self.client_hs.secret = expand_label(&self.handshake_prk, b"c hs traffic", th_sh);
        self.server_hs.secret = expand_label(&self.handshake_prk, b"s hs traffic", th_sh);
        Ok(())
    }

    pub(super) fn derive_application(&mut self, th_finished: &[u8; 32]) -> Result<(), OnionError> {
        let c = crypto();
        let zeros = [0u8; 32];
        let derived = expand_label(&self.handshake_prk, b"derived", &[]);
        c.hkdf_extract(&derived, &zeros, &mut self.master_prk);
        self.client_app.secret = expand_label(&self.master_prk, b"c ap traffic", th_finished);
        self.server_app.secret = expand_label(&self.master_prk, b"s ap traffic", th_finished);
        Ok(())
    }
}

pub(super) fn expand_label(prk: &[u8; 32], label: &[u8], context: &[u8]) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(&(32u16).to_be_bytes());
    let mut full = Vec::new();
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = [0u8; 32];
    crypto().hkdf_expand(prk, &info, &mut out);
    out
}
