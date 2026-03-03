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


use alloc::{vec, vec::Vec};
use crate::network::onion::OnionError;
use super::constants::{KEY_LEN, IV_LEN, NTOR_ONIONSKIN_LEN, NTOR_REPLY_LEN};
use super::provider::provider;

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    Initial,
    Sent,
    Complete,
    Failed,
}

#[derive(Debug)]
pub struct HopCrypto {
    pub forward_key: Vec<u8>,
    pub backward_key: Vec<u8>,
    pub forward_iv: Vec<u8>,
    pub backward_iv: Vec<u8>,

    handshake_state: HandshakeState,

    sk: [u8; 32],
    pk: [u8; 32],

    server_pk: Option<[u8; 32]>,
    shared_secret: Option<[u8; 32]>,

    client_nonce: [u8; 32],
}

impl HopCrypto {
    pub fn new(relay_onion_key: &[u8]) -> Result<Self, OnionError> {
        if relay_onion_key.len() != 32 {
            return Err(OnionError::CryptoError);
        }
        let (sk, pk) = provider().x25519_generate_keypair()?;
        let mut nonce = [0u8; 32];
        provider().random_bytes(&mut nonce)?;

        Ok(Self {
            forward_key: vec![0u8; KEY_LEN],
            backward_key: vec![0u8; KEY_LEN],
            forward_iv: vec![0u8; IV_LEN],
            backward_iv: vec![0u8; IV_LEN],
            handshake_state: HandshakeState::Initial,
            sk,
            pk,
            server_pk: None,
            shared_secret: None,
            client_nonce: nonce,
        })
    }

    pub fn handshake_data(&mut self) -> Vec<u8> {
        if self.handshake_state != HandshakeState::Initial {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(NTOR_ONIONSKIN_LEN);
        out.extend_from_slice(&self.pk);
        out.extend_from_slice(&self.client_nonce);
        let mut pad = [0u8; NTOR_ONIONSKIN_LEN - 64];
        let _ = provider().random_bytes(&mut pad);
        out.extend_from_slice(&pad);
        self.handshake_state = HandshakeState::Sent;
        out
    }

    pub fn complete_handshake(&mut self, response: &[u8]) -> Result<(), OnionError> {
        if self.handshake_state != HandshakeState::Sent {
            return Err(OnionError::CryptoError);
        }
        if response.len() < NTOR_REPLY_LEN {
            return Err(OnionError::InvalidCell);
        }

        let mut spk = [0u8; 32];
        spk.copy_from_slice(&response[..32]);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&response[32..64]);

        let shared = provider().x25519(&self.sk, &spk)?;
        self.server_pk = Some(spk);
        self.shared_secret = Some(shared);

        let mut auth_msg = Vec::with_capacity(6 + 32 + 32 + 32);
        auth_msg.extend_from_slice(b"ntor-auth");
        auth_msg.extend_from_slice(&self.client_nonce);
        auth_msg.extend_from_slice(&spk);
        auth_msg.extend_from_slice(&self.pk);
        let mut expect = [0u8; 32];
        provider().hmac_sha256(shared.as_slice(), &auth_msg, &mut expect);
        if !provider().ct_eq(&expect, &tag) {
            self.handshake_state = HandshakeState::Failed;
            return Err(OnionError::CryptoError);
        }

        let mut prk = [0u8; 32];
        provider().hmac_sha256(shared.as_slice(), b"ntor-prk", &mut prk);

        let mut info = Vec::with_capacity(16 + 32 + 32 + 32);
        info.extend_from_slice(b"NONOS_ONION_KDF");
        info.extend_from_slice(&self.client_nonce);
        info.extend_from_slice(&spk);
        info.extend_from_slice(&self.pk);

        const OUT_LEN: usize = KEY_LEN * 2 + IV_LEN * 2;
        let mut okm = [0u8; OUT_LEN];
        provider().hkdf_sha256_expand(&prk, &info, &mut okm);

        self.forward_key.copy_from_slice(&okm[0..KEY_LEN]);
        self.backward_key.copy_from_slice(&okm[KEY_LEN..KEY_LEN * 2]);
        self.forward_iv
            .copy_from_slice(&okm[KEY_LEN * 2..KEY_LEN * 2 + IV_LEN]);
        self.backward_iv
            .copy_from_slice(&okm[KEY_LEN * 2 + IV_LEN..KEY_LEN * 2 + IV_LEN * 2]);

        self.handshake_state = HandshakeState::Complete;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.handshake_state == HandshakeState::Complete
    }
}
