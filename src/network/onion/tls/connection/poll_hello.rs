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

use super::super::aead::AeadState;
use super::super::crypto_provider::crypto;
use super::super::io::{try_read, write_all};
use super::super::protocol::{
    build_client_hello_retry, has_tls12_downgrade_sentinel, parse_handshake_view,
    parse_server_hello, wrap_record, ServerHelloResult,
};
use super::super::types::{CipherSuite, ContentType, HSType, TlsSessionInfo, TLS_1_2};
use super::types::{HandshakePhase, TLSConnection};
use crate::network::onion::OnionError;
use crate::network::tcp::TcpSocket;
use alloc::vec;

impl TLSConnection {
    pub(super) fn poll_server_hello(
        &mut self,
        sock: &TcpSocket,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        let mut buf = vec![0u8; 16384];
        let n = match try_read(sock, &mut buf) {
            Ok(n) if n > 0 => n,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e),
        };
        self.recv_buffer.extend_from_slice(&buf[..n]);

        let mut sh_result: Option<ServerHelloResult> = None;
        let mut sh_raw: Option<alloc::vec::Vec<u8>> = None;
        let mut cur = &self.recv_buffer[..];
        while cur.len() >= 5 {
            let ct = cur[0];
            let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;
            if cur.len() < 5 + len {
                break;
            }
            let payload = &cur[5..5 + len];
            match ct {
                x if x == ContentType::Handshake as u8 => {
                    let mut hp = payload;
                    while hp.len() >= 4 {
                        let (typ, body, adv) = parse_handshake_view(hp)?;
                        if typ == HSType::ServerHello as u8 {
                            sh_raw = Some(hp[..adv].to_vec());
                            sh_result = Some(parse_server_hello(body)?);
                        }
                        hp = &hp[adv..];
                    }
                }
                x if x == ContentType::Alert as u8 => {
                    crate::sys::serial::print(b"[TLS] ERROR: server Alert during ServerHello");
                    if payload.len() >= 2 {
                        crate::sys::serial::print(b" level=");
                        crate::sys::serial::print_dec(payload[0] as u64);
                        crate::sys::serial::print(b" desc=");
                        crate::sys::serial::print_dec(payload[1] as u64);
                    }
                    crate::sys::serial::println(b"");
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::NetworkError);
                }
                x if x == ContentType::ApplicationData as u8 => break,
                _ => {}
            }
            cur = &cur[5 + len..];
        }

        let result = match sh_result {
            Some(r) => r,
            None => return Ok(None),
        };

        // Consume processed bytes from recv_buffer
        let consumed = self.recv_buffer.len() - cur.len();
        self.recv_buffer.drain(..consumed);

        match result {
            ServerHelloResult::HelloRetryRequest { suite, selected_group, cookie } => {
                self.handle_hrr(sock, suite, selected_group, cookie, sh_raw.as_deref())
            }
            ServerHelloResult::Normal { suite, server_pub, server_group, random, psk_selected } => {
                self.handle_normal_sh(
                    suite,
                    server_pub,
                    server_group,
                    random,
                    sh_raw.as_deref(),
                    psk_selected,
                )
            }
        }
    }

    /// Handle a HelloRetryRequest: transcript rewrite, generate new keypair, send ClientHello2.
    fn handle_hrr(
        &mut self,
        sock: &TcpSocket,
        suite: u16,
        selected_group: u16,
        cookie: Option<alloc::vec::Vec<u8>>,
        sh_raw: Option<&[u8]>,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        // RFC 8446 §4.1.4: A client MUST NOT process more than one HRR
        if self.hrr_count >= 1 {
            self.phase = HandshakePhase::Failed;
            return Err(OnionError::CryptoError);
        }
        self.hrr_count += 1;

        // Set cipher suite from HRR so transcript uses the correct hash
        self.suite = match suite {
            0x1301 => CipherSuite::TlsAes128GcmSha256,
            0x1302 => CipherSuite::TlsAes256GcmSha384,
            0x1303 => CipherSuite::TlsChacha20Poly1305Sha256,
            _ => {
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::CryptoError);
            }
        };
        self.transcript.set_suite(self.suite);
        self.ks.set_suite(self.suite);

        // Step 1: Transcript rewrite — replace CH1 hash with synthetic message_hash
        self.transcript.replace_with_message_hash();

        // Step 2: Add HRR (as ServerHello) to transcript
        if let Some(raw) = sh_raw {
            self.transcript.add_raw(raw);
        }

        // Step 3: Generate new keypair for the server's selected group
        let c = crypto();
        let (group_id, pub_key) = match selected_group {
            // X25519
            0x001d => {
                let (pk, sk) = c.x25519_keypair()?;
                self.ephemeral_x25519 = sk;
                (0x001du16, pk.to_vec())
            }
            // P-256 (secp256r1)
            0x0017 => {
                let (sk, pk) = c.p256_keypair()?;
                self.ephemeral_p256 = sk;
                (0x0017u16, pk.to_vec())
            }
            _ => {
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::CryptoError);
            }
        };
        self.server_group = selected_group;

        // Step 4: Build ClientHello2 with the new key share (and cookie if present)
        let sni_ref = self.sni_cache.as_deref();
        let alpn_strings: Option<alloc::vec::Vec<&str>> =
            self.alpn_cache.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect());
        let alpn_slice: Option<&[&str]> = alpn_strings.as_deref();

        let key_shares: &[(u16, &[u8])] = &[(group_id, &pub_key)];
        let cookie_ref = cookie.as_deref();
        let ch2 = build_client_hello_retry(
            &self.client_random,
            sni_ref,
            alpn_slice,
            key_shares,
            cookie_ref,
        );

        // Step 5: Add ClientHello2 to transcript, send it
        self.transcript.add_handshake(&ch2);
        write_all(sock, &wrap_record(ContentType::Handshake as u8, TLS_1_2, &ch2), 10_000)?;

        // Stay in SentClientHello — server will send a real ServerHello next
        self.phase = HandshakePhase::SentClientHello;
        Ok(None)
    }

    /// Handle a normal ServerHello: ECDH key agreement, derive handshake keys.
    fn handle_normal_sh(
        &mut self,
        suite: u16,
        server_pub: alloc::vec::Vec<u8>,
        server_group: u16,
        random: [u8; 32],
        sh_raw: Option<&[u8]>,
        psk_selected: Option<u16>,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        self.server_random = random;

        if has_tls12_downgrade_sentinel(&self.server_random) {
            self.phase = HandshakePhase::Failed;
            return Err(OnionError::CryptoError);
        }

        self.suite = match suite {
            0x1301 => CipherSuite::TlsAes128GcmSha256,
            0x1302 => CipherSuite::TlsAes256GcmSha384,
            0x1303 => CipherSuite::TlsChacha20Poly1305Sha256,
            _ => {
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::CryptoError);
            }
        };

        // Configure transcript and key schedule for the negotiated hash
        // MUST be before adding ServerHello to transcript so the hash is correct
        self.transcript.set_suite(self.suite);
        self.ks.set_suite(self.suite);

        // Add ServerHello to transcript (now hashed with the correct algorithm)
        if let Some(raw) = sh_raw {
            self.transcript.add_raw(raw);
        }

        self.server_pub = server_pub;
        self.server_group = server_group;

        // ECDH key agreement — dispatch by negotiated group
        let c = crypto();
        let shared = match server_group {
            // X25519
            0x001d => {
                if self.server_pub.len() != 32 {
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::CryptoError);
                }
                let mut spub = [0u8; 32];
                spub.copy_from_slice(&self.server_pub);
                let result = c.x25519(&self.ephemeral_x25519, &spub);
                result?
            }
            // P-256 (secp256r1)
            0x0017 => {
                if self.server_pub.len() != 65 {
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::CryptoError);
                }
                let mut spub = [0u8; 65];
                spub.copy_from_slice(&self.server_pub);
                let result = c.p256_ecdh(&self.ephemeral_p256, &spub);
                result?
            }
            _ => {
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::CryptoError);
            }
        };

        // If server accepted our PSK (pre_shared_key extension present with index 0),
        // use PSK-based key derivation; otherwise standard derivation.
        if let Some(0) = psk_selected {
            if self.using_psk {
                if let Some(ref psk) = self.psk_value {
                    crate::sys::serial::println(b"[TLS] server accepted PSK resumption");
                    self.ks.derive_after_sh_with_psk(&shared, psk, self.transcript.hash())?;
                } else {
                    // PSK value missing — should not happen
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::CryptoError);
                }
            } else {
                // Server selected PSK but we didn't offer one — protocol violation
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::CryptoError);
            }
        } else if psk_selected.is_some() {
            // Server selected a PSK index > 0 — we only ever offer one identity (index 0)
            self.phase = HandshakePhase::Failed;
            return Err(OnionError::CryptoError);
        } else {
            // No PSK selected — this is a full handshake
            self.using_psk = false;
            self.ks.derive_after_sh(&shared, self.transcript.hash())?;
        }

        self.rx_hs = AeadState::from_secret(&self.ks.server_hs, self.suite)?;
        self.tx_hs = AeadState::from_secret(&self.ks.client_hs, self.suite)?;

        self.phase = HandshakePhase::ReceivedServerHello;
        Ok(None)
    }
}
