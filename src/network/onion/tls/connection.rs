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
use super::verify::{get_cert_verifier, CertVerifier, X509};
use super::crypto_provider::crypto;
use super::io::{read_some, write_all};

pub struct TLSConnection {
    suite: CipherSuite,
    transcript: Transcript,
    ks: KeySchedule,
    rx_hs: AeadState,
    tx_hs: AeadState,
    rx_app: Option<AeadState>,
    tx_app: Option<AeadState>,
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
        }
    }

    pub fn handshake_full(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
        _verifier: &'static dyn CertVerifier,
    ) -> Result<TlsSessionInfo, OnionError> {
        let c = crypto();

        let mut client_random = [0u8; 32];
        c.random(&mut client_random)?;
        let (esk, epk) = c.x25519_keypair()?;

        let ch = build_client_hello(&client_random, sni, alpn, &epk);
        self.transcript.add_handshake(&ch);
        write_all(sock, &wrap_record(ContentType::Handshake as u8, TLS_1_2, &ch), 10_000)?;

        let mut server_pub = [0u8; 32];
        let mut server_chosen_suite = 0u16;
        let mut server_random = [0u8; 32];

        loop {
            let mut buf = vec![0u8; 4096];
            let n = read_some(sock, &mut buf, 15_000)?;
            if n == 0 {
                return Err(OnionError::NetworkError);
            }
            let mut cur = &buf[..n];

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
                                server_pub.copy_from_slice(&sv_pub);
                                server_random.copy_from_slice(&sv_random);
                            }
                            hp = &hp[adv..];
                        }
                    }
                    x if x == ContentType::ChangeCipherSpec as u8 => {}
                    x if x == ContentType::Alert as u8 => return Err(OnionError::NetworkError),
                    _ => {}
                }
                cur = &cur[5 + len..];
            }
            if server_chosen_suite != 0 {
                break;
            }
        }

        if has_tls12_downgrade_sentinel(&server_random) {
            return Err(OnionError::CryptoError);
        }

        self.suite = match server_chosen_suite {
            0x1301 => CipherSuite::TlsAes128GcmSha256,
            0x1303 => CipherSuite::TlsChacha20Poly1305Sha256,
            _ => return Err(OnionError::CryptoError),
        };

        let shared = c.x25519(&esk, &server_pub)?;
        let th_sh = *self.transcript.hash();
        self.ks.derive_after_sh(&shared, &th_sh)?;

        self.rx_hs = AeadState::from_secret(&self.ks.server_hs, self.suite)?;
        self.tx_hs = AeadState::from_secret(&self.ks.client_hs, self.suite)?;

        let mut got_finished = false;
        let mut server_certs: Vec<Vec<u8>> = Vec::new();
        let mut cert_verify_alg: Option<u16> = None;
        let mut cert_verify_sig: Vec<u8> = Vec::new();

        'outer: for _ in 0..32 {
            let mut buf = vec![0u8; 8192];
            let n = read_some(sock, &mut buf, 20_000)?;
            if n == 0 {
                return Err(OnionError::NetworkError);
            }
            let mut cur = &buf[..n];

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
                        if inner_type != ContentType::Handshake as u8 {
                            cur = &cur[5 + len..];
                            continue;
                        }
                        let mut hp = data;
                        while hp.len() >= 4 {
                            let (typ, hbody, adv) = parse_handshake_view(hp)?;
                            self.transcript.add_raw(&hp[..adv]);

                            if typ == HSType::EncryptedExtensions as u8 {
                            } else if typ == HSType::Certificate as u8 {
                                server_certs = parse_certificate_chain(hbody)?;
                            } else if typ == HSType::CertificateVerify as u8 {
                                let (alg, sig) = parse_certificate_verify(hbody)?;
                                cert_verify_alg = Some(alg);
                                cert_verify_sig = sig;
                            } else if typ == HSType::Finished as u8 {
                                if !verify_finished_with_payload(&self.ks.server_hs, self.transcript.hash(), hbody) {
                                    return Err(OnionError::CryptoError);
                                }
                                got_finished = true;
                            }
                            hp = &hp[adv..];
                        }
                    }
                    x if x == ContentType::ChangeCipherSpec as u8 => {}
                    x if x == ContentType::Alert as u8 => return Err(OnionError::NetworkError),
                    _ => {}
                }

                cur = &cur[5 + len..];
            }

            if got_finished {
                break 'outer;
            }
        }

        if !got_finished {
            return Err(OnionError::NetworkError);
        }
        if server_certs.is_empty() {
            return Err(OnionError::AuthenticationFailed);
        }

        get_cert_verifier()
            .ok_or(OnionError::AuthenticationFailed)?
            .verify(&server_certs, sni.unwrap_or(""))?;

        if let Some(alg) = cert_verify_alg.as_ref() {
            let leaf = X509::parse_der(&server_certs[0])?;
            let (pk_kind, pk_bytes) = X509::public_key_info(&leaf)?;
            let to_be_signed = build_cert_verify_context(self.transcript.hash());
            let ok = match *alg {
                0x0807 => {
                    if pk_kind != super::types::PublicKeyKind::Ed25519 {
                        false
                    } else {
                        c.verify_ed25519(&pk_bytes, &to_be_signed, &cert_verify_sig)
                    }
                }
                0x0804 => {
                    if pk_kind != super::types::PublicKeyKind::Rsa {
                        false
                    } else {
                        c.verify_rsa_pss_sha256(&pk_bytes, &to_be_signed, &cert_verify_sig)
                    }
                }
                0x0403 => {
                    if pk_kind != super::types::PublicKeyKind::EcdsaP256 {
                        false
                    } else {
                        c.verify_ecdsa_p256_sha256(&pk_bytes, &to_be_signed, &cert_verify_sig)
                    }
                }
                _ => false,
            };
            if !ok {
                return Err(OnionError::AuthenticationFailed);
            }
        } else {
            return Err(OnionError::AuthenticationFailed);
        }

        let my_finished = build_finished(&self.ks.client_hs, self.transcript.hash());
        self.transcript.add_handshake(&my_finished);
        let enc = self.tx_hs.seal(self.suite, ContentType::Handshake, &my_finished)?;
        write_all(sock, &wrap_record(ContentType::ApplicationData as u8, TLS_1_2, &enc), 10_000)?;

        self.ks.derive_application(self.transcript.hash())?;
        self.rx_app = Some(AeadState::from_secret(&self.ks.server_app, self.suite)?);
        self.tx_app = Some(AeadState::from_secret(&self.ks.client_app, self.suite)?);

        Ok(TlsSessionInfo {
            cipher_suite: self.suite as u16,
            client_app_traffic_secret: self.ks.client_app.secret.to_vec(),
            server_app_traffic_secret: self.ks.server_app.secret.to_vec(),
        })
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
