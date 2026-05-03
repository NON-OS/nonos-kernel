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
use crate::crypto::chacha20poly1305::{aead_decrypt, aead_encrypt};
use crate::crypto::ed25519::{verify, KeyPair};
use crate::crypto::fill_random_bytes;
use alloc::vec::Vec;

pub struct TlsHandshake {
    state: HandshakeState,
    client_random: [u8; 32],
    server_random: [u8; 32],
    premaster_secret: [u8; 32],
    master_secret: [u8; 48],
}

#[derive(Debug, PartialEq)]
enum HandshakeState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    CertificateReceived,
    KeyExchangeComplete,
    Finished,
}

impl TlsHandshake {
    pub fn new() -> Self {
        let mut client_random = [0u8; 32];
        fill_random_bytes(&mut client_random);

        Self {
            state: HandshakeState::Initial,
            client_random,
            server_random: [0u8; 32],
            premaster_secret: [0u8; 32],
            master_secret: [0u8; 48],
        }
    }

    pub fn send_client_hello(&mut self) -> Vec<u8> {
        self.state = HandshakeState::ClientHelloSent;

        let mut message = Vec::new();
        message.extend_from_slice(&[0x16, 0x03, 0x03]);
        message.extend_from_slice(&self.client_random);
        message.extend_from_slice(b"TLS_CHACHA20_POLY1305_SHA256");
        message
    }

    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.state != HandshakeState::ClientHelloSent {
            return Err("Invalid handshake state");
        }

        if data.len() < 32 {
            return Err("Invalid server hello");
        }

        self.server_random.copy_from_slice(&data[0..32]);
        self.state = HandshakeState::ServerHelloReceived;
        Ok(())
    }

    pub fn process_certificate(&mut self, cert_data: &[u8]) -> Result<[u8; 32], &'static str> {
        if self.state != HandshakeState::ServerHelloReceived {
            return Err("Invalid handshake state");
        }

        if cert_data.len() < 32 {
            return Err("Invalid certificate");
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&cert_data[0..32]);

        self.state = HandshakeState::CertificateReceived;
        Ok(public_key)
    }

    pub fn generate_key_exchange(&mut self) -> Vec<u8> {
        fill_random_bytes(&mut self.premaster_secret);
        self.derive_master_secret();
        self.state = HandshakeState::KeyExchangeComplete;
        self.premaster_secret.to_vec()
    }

    fn derive_master_secret(&mut self) {
        let mut input = Vec::new();
        input.extend_from_slice(b"master secret");
        input.extend_from_slice(&self.client_random);
        input.extend_from_slice(&self.server_random);

        let hash = crate::crypto::sha256::hash(&input);
        self.master_secret[0..32].copy_from_slice(&hash);

        let mut input2 = Vec::new();
        input2.extend_from_slice(&hash);
        input2.extend_from_slice(&self.premaster_secret);
        let hash2 = crate::crypto::sha256::hash(&input2);
        self.master_secret[32..48].copy_from_slice(&hash2[0..16]);
    }

    pub fn finish_handshake(&mut self) -> Result<(), &'static str> {
        if self.state != HandshakeState::KeyExchangeComplete {
            return Err("Invalid handshake state");
        }

        self.state = HandshakeState::Finished;
        Ok(())
    }

    pub fn get_session_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        if self.state != HandshakeState::Finished {
            return None;
        }

        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];

        client_key.copy_from_slice(&self.master_secret[0..32]);
        server_key.copy_from_slice(&self.master_secret[16..48]);

        Some((client_key, server_key))
    }

    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Finished
    }
}
