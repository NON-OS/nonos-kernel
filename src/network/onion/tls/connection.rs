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
use crate::network::tcp::TcpSocket;
use crate::network::onion::OnionError;

use super::types::{CipherSuite, ContentType, HSType, TlsSessionInfo, TLS_1_2};
use super::transcript::Transcript;
use super::keys::KeySchedule;
use super::aead::AeadState;
use super::protocol::{
    build_client_hello, build_finished, build_cert_verify_context, has_tls12_downgrade_sentinel,
    parse_certificate_chain, parse_certificate_verify, parse_handshake_view, parse_server_hello,
    verify_finished_with_payload, wrap_record,
};
use super::verify::{CertVerifier, X509};
use super::crypto_provider::crypto;
use super::io::{write_all, try_read};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    Idle,
    SentClientHello,
    ReceivedServerHello,
    ReceivedEncrypted,
    SentFinished,
    Complete,
    Failed,
}

pub struct TLSConnection {
    suite: CipherSuite,
    transcript: Transcript,
    ks: KeySchedule,
    rx_hs: AeadState,
    tx_hs: AeadState,
    rx_app: Option<AeadState>,
    tx_app: Option<AeadState>,
    phase: HandshakePhase,
    client_random: [u8; 32],
    ephemeral_secret: Vec<u8>,
    server_random: [u8; 32],
    server_pub: [u8; 32],
    server_certs: Vec<Vec<u8>>,
    cert_verify_alg: Option<u16>,
    cert_verify_sig: Vec<u8>,
    got_finished: bool,
    recv_buffer: Vec<u8>,
}

impl Drop for TLSConnection {
    fn drop(&mut self) {
        for byte in self.ephemeral_secret.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.client_random.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl TLSConnection {
    pub fn new() -> Self {
        Self {
            suite: CipherSuite::TlsAes128GcmSha256,
            transcript: Transcript::new(),
            ks: KeySchedule::new(),
            rx_hs: AeadState::empty(),
            tx_hs: AeadState::empty(),
            rx_app: None,
            tx_app: None,
            phase: HandshakePhase::Idle,
            client_random: [0u8; 32],
            ephemeral_secret: Vec::new(),
            server_random: [0u8; 32],
            server_pub: [0u8; 32],
            server_certs: Vec::new(),
            cert_verify_alg: None,
            cert_verify_sig: Vec::new(),
            got_finished: false,
            recv_buffer: Vec::new(),
        }
    }

    pub fn start_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
    ) -> Result<(), OnionError> {
        if self.phase != HandshakePhase::Idle {
            return Err(OnionError::CryptoError);
        }

        let c = crypto();
        c.random(&mut self.client_random)?;
        let (epk, esk) = c.x25519_keypair()?;
        self.ephemeral_secret = esk.to_vec();

        let ch = build_client_hello(&self.client_random, sni, alpn, &epk);
        self.transcript.add_handshake(&ch);
        write_all(sock, &wrap_record(ContentType::Handshake as u8, TLS_1_2, &ch), 10_000)?;

        self.phase = HandshakePhase::SentClientHello;
        Ok(())
    }

    pub fn poll_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        match self.phase {
            HandshakePhase::Idle => Err(OnionError::CryptoError),
            HandshakePhase::Complete => {
                Ok(Some(TlsSessionInfo {
                    cipher_suite: self.suite as u16,
                    client_app_traffic_secret: self.ks.client_app.secret.to_vec(),
                    server_app_traffic_secret: self.ks.server_app.secret.to_vec(),
                }))
            }
            HandshakePhase::Failed => Err(OnionError::CryptoError),
            HandshakePhase::SentClientHello => {
                crate::sys::serial::println(b"[TLS] poll: SentClientHello");
                self.poll_server_hello(sock)
            }
            HandshakePhase::ReceivedServerHello => {
                crate::sys::serial::println(b"[TLS] poll: ReceivedServerHello");
                self.poll_encrypted(sock)
            }
            HandshakePhase::ReceivedEncrypted => {
                crate::sys::serial::println(b"[TLS] poll: ReceivedEncrypted");
                self.finish_handshake(sock, sni, verifier)
            }
            HandshakePhase::SentFinished => {
                self.phase = HandshakePhase::Complete;
                Ok(Some(TlsSessionInfo {
                    cipher_suite: self.suite as u16,
                    client_app_traffic_secret: self.ks.client_app.secret.to_vec(),
                    server_app_traffic_secret: self.ks.server_app.secret.to_vec(),
                }))
            }
        }
    }

    fn poll_server_hello(&mut self, sock: &TcpSocket) -> Result<Option<TlsSessionInfo>, OnionError> {
        let mut buf = vec![0u8; 16384];
        let n = match try_read(sock, &mut buf) {
            Ok(n) if n > 0 => n,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e),
        };

        self.recv_buffer.extend_from_slice(&buf[..n]);
        let mut server_chosen_suite = 0u16;

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
                            self.transcript.add_raw(&hp[..adv]);
                            let (suite, sv_pub, sv_random) = parse_server_hello(body)?;
                            server_chosen_suite = suite;
                            self.server_pub.copy_from_slice(&sv_pub);
                            self.server_random.copy_from_slice(&sv_random);
                        }
                        hp = &hp[adv..];
                    }
                }
                x if x == ContentType::ChangeCipherSpec as u8 => {}
                x if x == ContentType::Alert as u8 => {
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::NetworkError);
                }
                x if x == ContentType::ApplicationData as u8 => {
                    break;
                }
                _ => {}
            }
            cur = &cur[5 + len..];
        }

        if server_chosen_suite == 0 {
            return Ok(None);
        }

        if has_tls12_downgrade_sentinel(&self.server_random) {
            self.phase = HandshakePhase::Failed;
            return Err(OnionError::CryptoError);
        }

        self.suite = match server_chosen_suite {
            0x1301 => CipherSuite::TlsAes128GcmSha256,
            0x1303 => CipherSuite::TlsChacha20Poly1305Sha256,
            _ => {
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::CryptoError);
            }
        };

        let c = crypto();
        let mut esk = [0u8; 32];
        esk.copy_from_slice(&self.ephemeral_secret);
        let shared = c.x25519(&esk, &self.server_pub)?;
        let th_sh = *self.transcript.hash();
        self.ks.derive_after_sh(&shared, &th_sh)?;

        self.rx_hs = AeadState::from_secret(&self.ks.server_hs, self.suite)?;
        self.tx_hs = AeadState::from_secret(&self.ks.client_hs, self.suite)?;

        let consumed = self.recv_buffer.len() - cur.len();
        self.recv_buffer.drain(..consumed);
        self.phase = HandshakePhase::ReceivedServerHello;
        Ok(None)
    }

    fn poll_encrypted(&mut self, sock: &TcpSocket) -> Result<Option<TlsSessionInfo>, OnionError> {
        let mut buf = vec![0u8; 16384];
        match try_read(sock, &mut buf) {
            Ok(n) if n > 0 => {
                self.recv_buffer.extend_from_slice(&buf[..n]);
            }
            Ok(_) => {
                if self.recv_buffer.is_empty() {
                    return Ok(None);
                }
            }
            Err(e) => return Err(e),
        };

        let mut cur = &self.recv_buffer[..];

        while cur.len() >= 5 {
            let ct = cur[0];
            let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;

            if cur.len() < 5 + len {
                break;
            }
            let body = &cur[5..5 + len];

            match ct {
                x if x == ContentType::ApplicationData as u8 => {
                    let plaintext = self.rx_hs.open(self.suite, ContentType::ApplicationData, body)?;
                    let (&inner_type, data) = plaintext.split_last().ok_or(OnionError::CryptoError)?;
                    if inner_type == ContentType::Handshake as u8 {
                        let mut hp = data;
                        while hp.len() >= 4 {
                            let (typ, hbody, adv) = parse_handshake_view(hp)?;

                            if typ == HSType::Finished as u8 {
                                crate::sys::serial::println(b"[TLS] got Finished");
                                if !verify_finished_with_payload(&self.ks.server_hs, self.transcript.hash(), hbody) {
                                    crate::sys::serial::println(b"[TLS] Finished verify FAILED");
                                    self.phase = HandshakePhase::Failed;
                                    return Err(OnionError::CryptoError);
                                }
                                crate::sys::serial::println(b"[TLS] Finished verify OK");
                                self.transcript.add_raw(&hp[..adv]);
                                self.got_finished = true;
                            } else {
                                self.transcript.add_raw(&hp[..adv]);
                                if typ == HSType::Certificate as u8 {
                                    crate::sys::serial::println(b"[TLS] got Certificate");
                                    self.server_certs = parse_certificate_chain(hbody)?;
                                } else if typ == HSType::CertificateVerify as u8 {
                                    crate::sys::serial::println(b"[TLS] got CertificateVerify");
                                    let (alg, sig) = parse_certificate_verify(hbody)?;
                                    self.cert_verify_alg = Some(alg);
                                    self.cert_verify_sig = sig;
                                }
                            }
                            hp = &hp[adv..];
                        }
                    }
                }
                x if x == ContentType::ChangeCipherSpec as u8 => {}
                x if x == ContentType::Alert as u8 => {
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::NetworkError);
                }
                _ => {}
            }

            cur = &cur[5 + len..];
        }

        let consumed = self.recv_buffer.len() - cur.len();
        if consumed > 0 {
            self.recv_buffer.drain(..consumed);
        }

        if self.got_finished {
            crate::sys::serial::println(b"[TLS] setting phase=ReceivedEncrypted");
            self.phase = HandshakePhase::ReceivedEncrypted;
        }

        Ok(None)
    }

    fn finish_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        crate::sys::serial::println(b"[TLS] finish_handshake called");

        if self.server_certs.is_empty() {
            crate::sys::serial::println(b"[TLS] ERROR: no certs");
            self.phase = HandshakePhase::Failed;
            return Err(OnionError::AuthenticationFailed);
        }

        crate::sys::serial::print(b"[TLS] verifying ");
        crate::sys::serial::print_dec(self.server_certs.len() as u64);
        crate::sys::serial::println(b" certs");

        if let Err(e) = verifier.verify(&self.server_certs, sni.unwrap_or("")) {
            crate::sys::serial::println(b"[TLS] ERROR: cert verify failed");
            return Err(e);
        }
        crate::sys::serial::println(b"[TLS] cert verify OK");

        if let Some(alg) = self.cert_verify_alg.as_ref() {
            crate::sys::serial::print(b"[TLS] cert_verify alg=0x");
            crate::sys::serial::print_hex(*alg as u64);
            crate::sys::serial::println(b"");

            let leaf = X509::parse_der(&self.server_certs[0])?;
            let (pk_kind, pk_bytes) = X509::public_key_info(&leaf)?;
            let to_be_signed = build_cert_verify_context(self.transcript.hash());
            let c = crypto();
            let ok = match *alg {
                0x0807 => {
                    if pk_kind != super::types::PublicKeyKind::Ed25519 { false }
                    else { c.verify_ed25519(&pk_bytes, &to_be_signed, &self.cert_verify_sig) }
                }
                0x0804 => {
                    if pk_kind != super::types::PublicKeyKind::Rsa { false }
                    else { c.verify_rsa_pss_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig) }
                }
                0x0403 => {
                    if pk_kind != super::types::PublicKeyKind::EcdsaP256 { false }
                    else { c.verify_ecdsa_p256_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig) }
                }
                _ => false,
            };
            if !ok {
                crate::sys::serial::println(b"[TLS] ERROR: sig verify failed");
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::AuthenticationFailed);
            }
            crate::sys::serial::println(b"[TLS] sig verify OK");
        } else {
            crate::sys::serial::println(b"[TLS] ERROR: no cert_verify_alg");
            self.phase = HandshakePhase::Failed;
            return Err(OnionError::AuthenticationFailed);
        }

        let my_finished = build_finished(&self.ks.client_hs, self.transcript.hash());
        self.transcript.add_handshake(&my_finished);
        let enc = self.tx_hs.seal(self.suite, ContentType::Handshake, &my_finished)?;
        write_all(sock, &wrap_record(ContentType::ApplicationData as u8, TLS_1_2, &enc), 10_000)?;

        self.ks.derive_application(self.transcript.hash())?;
        self.rx_app = Some(AeadState::from_secret(&self.ks.server_app, self.suite)?);
        self.tx_app = Some(AeadState::from_secret(&self.ks.client_app, self.suite)?);

        crate::sys::serial::println(b"[TLS] handshake complete!");
        self.phase = HandshakePhase::SentFinished;
        Ok(None)
    }

    pub fn handshake_full(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<TlsSessionInfo, OnionError> {
        self.start_handshake(sock, sni, alpn)?;

        for _ in 0..100 {
            match self.poll_handshake(sock, sni, verifier)? {
                Some(info) => return Ok(info),
                None => {
                    for _ in 0..1000 { core::hint::spin_loop(); }
                }
            }
        }

        Err(OnionError::Timeout)
    }

    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }

    pub fn encrypt_app(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let state = self.tx_app.as_mut().ok_or(OnionError::CryptoError)?;
        state.seal(self.suite, ContentType::ApplicationData, plaintext)
    }

    pub fn decrypt_app(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let state = self.rx_app.as_mut().ok_or(OnionError::CryptoError)?;
        state.open(self.suite, ContentType::ApplicationData, ciphertext)
    }
}
