/*!
 TLS 1.3 Client (RFC 8446) for Onion Routing
*/

#![no_std]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::cmp::min;

use crate::network::{get_network_stack, tcp::TcpSocket};
use crate::time;

use super::OnionError;

/* ===== Wire constants & enums ===== */

const TLS_1_2: u16 = 0x0303;
const TLS_1_3: u16 = 0x0304;

#[repr(u8)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[repr(u8)]
enum HSType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsChacha20Poly1305Sha256 = 0x1303,
}

/* ===== Public types for integration ===== */

#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub cipher_suite: u16,
    pub client_app_traffic_secret: Vec<u8>,
    pub server_app_traffic_secret: Vec<u8>,
}

/* ===== Connection ===== */

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

    /// TLS 1.3 handshake (client).
    pub fn handshake_full(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
        _verifier: &'static dyn CertVerifier,
    ) -> Result<TlsSessionInfo, OnionError> {
        let crypto = crypto();

        /* ---- ClientHello ---- */
        let mut client_random = [0u8; 32];
        crypto.random(&mut client_random)?;
        let (esk, epk) = crypto.x25519_keypair()?;

        let ch = build_client_hello(&client_random, sni, alpn, &epk);
        self.transcript.add_handshake(&ch);
        write_all(sock, &wrap_record(ContentType::Handshake as u8, TLS_1_2, &ch), 10_000)?;

        /* ---- Receive up to and including ServerHello ---- */
        let mut server_pub = [0u8; 32];
        let mut server_chosen_suite = 0u16;
        let mut server_random = [0u8; 32];

        loop {
            let mut buf = vec![0u8; 4096];
            let n = read_some(sock, &mut buf, 15_000)?;
            if n == 0 { return Err(OnionError::NetworkError); }
            let mut cur = &buf[..n];

            while cur.len() >= 5 {
                let ct = cur[0];
                let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;
                if cur.len() < 5 + len { break; }
                let payload = &cur[5..5 + len];

                match ct {
                    x if x == ContentType::Handshake as u8 => {
                        let mut hp = payload;
                        while hp.len() >= 4 {
                            let (typ, body, adv) = parse_handshake_view(hp)?;
                            if typ == HSType::ServerHello as u8 {
                                // Push exact SH encoding into transcript
                                self.transcript.add_raw(&hp[..adv]);
                                let (suite, sv_pub, sv_random) = parse_server_hello(body)?;
                                server_chosen_suite = suite;
                                server_pub.copy_from_slice(&sv_pub);
                                server_random.copy_from_slice(&sv_random);
                            }
                            hp = &hp[adv..];
                        }
                    }
                    x if x == ContentType::ChangeCipherSpec as u8 => {
                        // Ignore CCS for middleboxes (per RFC 8446, Appendix D.4)
                    }
                    x if x == ContentType::Alert as u8 => return Err(OnionError::NetworkError),
                    _ => {}
                }
                cur = &cur[5 + len..];
            }
            if server_chosen_suite != 0 { break; }
        }

        // Reject downgrade sentinels in SH.random for TLS 1.3
        if has_tls12_downgrade_sentinel(&server_random) { return Err(OnionError::CryptoError); }

        self.suite = match server_chosen_suite {
            0x1301 => CipherSuite::TlsAes128GcmSha256,
            0x1303 => CipherSuite::TlsChacha20Poly1305Sha256,
            _ => return Err(OnionError::CryptoError),
        };

        /* ---- Derive handshake secrets using the actual transcript hash (CH||SH) ---- */
        let shared = crypto.x25519(&esk, &server_pub)?;
        let th_sh = *self.transcript.hash(); // Hash(CH || SH)
        self.ks.derive_after_sh(&shared, &th_sh)?;

        self.rx_hs = AeadState::from_secret(&self.ks.server_hs, self.suite)?;
        self.tx_hs = AeadState::from_secret(&self.ks.client_hs, self.suite)?;

        /* ---- Encrypted handshake flight: EE, Cert, CertVerify, Finished ---- */
        let mut got_finished = false;
        let mut server_certs: Vec<Vec<u8>> = Vec::new();
        let mut cert_verify_alg: Option<u16> = None;
        let mut cert_verify_sig: Vec<u8> = Vec::new();

        'outer: for _ in 0..32 {
            let mut buf = vec![0u8; 8192];
            let n = read_some(sock, &mut buf, 20_000)?;
            if n == 0 { return Err(OnionError::NetworkError); }
            let mut cur = &buf[..n];

            while cur.len() >= 5 {
                let ct = cur[0];
                let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;
                if cur.len() < 5 + len { break; }
                let body = &cur[5..5 + len];

                match ct {
                    x if x == ContentType::ApplicationData as u8 => {
                        // Decrypt with server handshake keys
                        let plaintext = self.rx_hs.open(self.suite, ContentType::ApplicationData, body)?;
                        // Split off inner content-type
                        if plaintext.is_empty() { return Err(OnionError::CryptoError); }
                        let (&inner_type, data) = plaintext.split_last().unwrap();
                        if inner_type != ContentType::Handshake as u8 {
                            // Ignore non-handshake (padding etc.)
                            cur = &cur[5 + len..];
                            continue;
                        }
                        // There may be multiple handshake messages inside
                        let mut hp = data;
                        while hp.len() >= 4 {
                            let (typ, hbody, adv) = parse_handshake_view(hp)?;
                            // Feed exact encoding into transcript
                            self.transcript.add_raw(&hp[..adv]);

                            if typ == HSType::EncryptedExtensions as u8 {
                                // OK
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
                    x if x == ContentType::ChangeCipherSpec as u8 => {
                        // Ignore CCS if any (middlebox mitigation)
                    }
                    x if x == ContentType::Alert as u8 => return Err(OnionError::NetworkError),
                    _ => {}
                }

                cur = &cur[5 + len..];
            }

            if got_finished { break 'outer; }
        }

        if !got_finished { return Err(OnionError::NetworkError); }
        if server_certs.is_empty() { return Err(OnionError::AuthenticationFailed); }

        /* ---- Link certificate policy and CertificateVerify signature ---- */
        // 1) Strict Tor link policy: single self-signed leaf
        CERT_VERIFIER
            .get()
            .ok_or(OnionError::AuthenticationFailed)?
            .verify(&server_certs, sni.unwrap_or(""))?;

        // 2) CertificateVerify: prove possession of leaf private key
        if let Some(alg) = cert_verify_alg.as_ref() {
            let leaf = X509::parse_der(&server_certs[0])?;
            let (pk_kind, pk_bytes) = X509::public_key_info(&leaf)?;
            let to_be_signed = build_cert_verify_context(self.transcript.hash());
            let ok = match *alg {
                0x0807 => { // ed25519
                    if pk_kind != PublicKeyKind::Ed25519 { false } else { crypto.verify_ed25519(&pk_bytes, &to_be_signed, &cert_verify_sig) }
                }
                0x0804 => { // rsa_pss_rsae_sha256
                    if pk_kind != PublicKeyKind::Rsa { false } else { crypto.verify_rsa_pss_sha256(&pk_bytes, &to_be_signed, &cert_verify_sig) }
                }
                0x0403 => { // ecdsa_secp256r1_sha256
                    if pk_kind != PublicKeyKind::EcdsaP256 { false } else { crypto.verify_ecdsa_p256_sha256(&pk_bytes, &to_be_signed, &cert_verify_sig) }
                }
                _ => false,
            };
            if !ok { return Err(OnionError::AuthenticationFailed); }
        } else {
            return Err(OnionError::AuthenticationFailed);
        }

        /* ---- Send our Finished (client) ---- */
        let my_finished = build_finished(&self.ks.client_hs, self.transcript.hash());
        self.transcript.add_handshake(&my_finished);
        let enc = self.tx_hs.seal(self.suite, ContentType::Handshake, &my_finished)?;
        write_all(sock, &wrap_record(ContentType::ApplicationData as u8, TLS_1_2, &enc), 10_000)?;

        /* ---- Derive application traffic secrets and switch ---- */
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

/* ===== Transcript ===== */

struct Transcript {
    state: [u8; 32],
    buffer: Vec<u8>,
}

impl Transcript {
    fn new() -> Self { Self { state: [0u8; 32], buffer: Vec::new() } }
    fn add_handshake(&mut self, hs: &[u8]) { self.buffer.extend_from_slice(hs); self.update(); }
    fn add_raw(&mut self, raw: &[u8]) { self.buffer.extend_from_slice(raw); self.update(); }
    fn update(&mut self) { crypto().sha256(&self.buffer, &mut self.state); }
    fn hash(&self) -> &[u8; 32] { &self.state }
}

/* ===== Key schedule ===== */

struct Secret { secret: [u8; 32] }

struct KeySchedule {
    early_prk: [u8; 32],
    handshake_prk: [u8; 32],
    master_prk: [u8; 32],
    client_hs: Secret,
    server_hs: Secret,
    client_app: Secret,
    server_app: Secret,
}

impl KeySchedule {
    fn new() -> Self {
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

    fn derive_after_sh(&mut self, shared: &[u8; 32], th_sh: &[u8; 32]) -> Result<(), OnionError> {
        let c = crypto();
        let zeros = [0u8; 32];

        // Early Secret = Extract(zeros, zeros)
        c.hkdf_extract(&zeros, &zeros, &mut self.early_prk);
        // derived = Expand-Label(early_prk, "derived", "", 32)
        let derived = expand_label(&self.early_prk, b"derived", &[]);
        // Handshake Secret = Extract(derived, ECDHE)
        c.hkdf_extract(&derived, shared, &mut self.handshake_prk);

        // hs traffic secrets using Hash(CH || SH)
        self.client_hs.secret = expand_label(&self.handshake_prk, b"c hs traffic", th_sh);
        self.server_hs.secret = expand_label(&self.handshake_prk, b"s hs traffic", th_sh);
        Ok(())
    }

    fn derive_application(&mut self, th_finished: &[u8; 32]) -> Result<(), OnionError> {
        let c = crypto();
        let zeros = [0u8; 32];
        let derived = expand_label(&self.handshake_prk, b"derived", &[]);
        c.hkdf_extract(&derived, &zeros, &mut self.master_prk);
        self.client_app.secret = expand_label(&self.master_prk, b"c ap traffic", th_finished);
        self.server_app.secret = expand_label(&self.master_prk, b"s ap traffic", th_finished);
        Ok(())
    }
}

/* ===== AEAD state ===== */

struct AeadState {
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl AeadState {
    fn empty() -> Self { Self { key: Vec::new(), iv: [0u8; 12], seq: 0 } }

    fn from_secret(sec: &Secret, suite: CipherSuite) -> Result<Self, OnionError> {
        let key_len = match suite { CipherSuite::TlsAes128GcmSha256 => 16, CipherSuite::TlsChacha20Poly1305Sha256 => 32 };
        let iv_full = expand_label(&sec.secret, b"iv", &[]);
        let mut iv = [0u8; 12]; iv.copy_from_slice(&iv_full[..12]);
        let key = expand_label(&sec.secret, b"key", &[])[..key_len].to_vec();
        Ok(Self { key, iv, seq: 0 })
    }

    #[inline]
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 { nonce[4 + i] ^= seq_bytes[i]; }
        nonce
    }

    fn seal(&mut self, suite: CipherSuite, inner_type: ContentType, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        // inner = plaintext || content_type
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(inner_type as u8);
        // AAD = outer record header with ciphertext length (which is inner.len() + 16)
        let total_len = (inner.len() + 16) as u16;
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData as u8;
        header[1..3].copy_from_slice(&TLS_1_2.to_be_bytes());
        header[3..5].copy_from_slice(&total_len.to_be_bytes());
        // AEAD
        let nonce = self.nonce();
        let ciphertext = crypto().aead_seal(suite, &self.key, &nonce, &header, &inner)?;
        self.seq = self.seq.wrapping_add(1);
        Ok(ciphertext)
    }

    fn open(&mut self, suite: CipherSuite, outer_type: ContentType, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut header = [0u8; 5];
        header[0] = outer_type as u8;
        header[1..3].copy_from_slice(&TLS_1_2.to_be_bytes());
        let total_len = ciphertext.len() as u16;
        header[3..5].copy_from_slice(&total_len.to_be_bytes());

        let nonce = self.nonce();
        let pt = crypto().aead_open(suite, &self.key, &nonce, &header, ciphertext)?;
        if pt.is_empty() { return Err(OnionError::CryptoError); }
        let (&last, data) = pt.split_last().unwrap();
        if last != ContentType::Handshake as u8 && last != ContentType::ApplicationData as u8 {
            return Err(OnionError::CryptoError);
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(data.to_vec())
    }
}

/* ===== Build & parse helpers ===== */

fn build_client_hello(
    client_random: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    epk: &[u8; 32],
) -> Vec<u8> {
    let mut ch = Vec::with_capacity(512);
    // legacy_version
    ch.extend_from_slice(&TLS_1_2.to_be_bytes());
    // random
    ch.extend_from_slice(client_random);
    // legacy_session_id
    ch.push(0);
    // cipher_suites
    let ciphers: [u16; 2] = [
        CipherSuite::TlsAes128GcmSha256 as u16,
        CipherSuite::TlsChacha20Poly1305Sha256 as u16,
    ];
    ch.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for cs in ciphers { ch.extend_from_slice(&cs.to_be_bytes()); }
    // compression
    ch.push(1); ch.push(0);

    // extensions
    let mut ext = Vec::with_capacity(256);

    // supported_versions
    {
        let mut body = Vec::new();
        body.push(2);
        body.extend_from_slice(&TLS_1_3.to_be_bytes());
        push_ext(&mut ext, 0x002b, &body);
    }

    // SNI
    if let Some(host) = sni {
        let hb = host.as_bytes();
        let mut sni_body = Vec::new();
        let mut list = Vec::new();
        list.push(0);
        list.extend_from_slice(&(hb.len() as u16).to_be_bytes());
        list.extend_from_slice(hb);
        sni_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(&list);
        push_ext(&mut ext, 0x0000, &sni_body);
    }

    // signature_algorithms
    {
        let sigs: [u16; 5] = [0x0403, 0x0804, 0x0805, 0x0806, 0x0807];
        let mut body = Vec::new();
        body.extend_from_slice(&((sigs.len() as u16) * 2).to_be_bytes());
        for s in sigs { body.extend_from_slice(&s.to_be_bytes()); }
        push_ext(&mut ext, 0x000d, &body);
    }

    // supported_groups
    {
        let groups: [u16; 2] = [0x001d, 0x0017];
        let mut body = Vec::new();
        body.extend_from_slice(&((groups.len() as u16) * 2).to_be_bytes());
        for g in groups { body.extend_from_slice(&g.to_be_bytes()); }
        push_ext(&mut ext, 0x000a, &body);
    }

    // key_share (x25519)
    {
        let mut ks = Vec::new();
        ks.extend_from_slice(&0x001d_u16.to_be_bytes());
        ks.extend_from_slice(&(epk.len() as u16).to_be_bytes());
        ks.extend_from_slice(epk);
        let mut body = Vec::new();
        body.extend_from_slice(&(ks.len() as u16).to_be_bytes());
        body.extend_from_slice(&ks);
        push_ext(&mut ext, 0x0033, &body);
    }

    // ALPN
    if let Some(protocols) = alpn {
        let mut alpn_body = Vec::new();
        let mut list = Vec::new();
        for p in protocols {
            let pb = p.as_bytes();
            if pb.len() > 255 { continue; }
            list.push(pb.len() as u8);
            list.extend_from_slice(pb);
        }
        alpn_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        alpn_body.extend_from_slice(&list);
        push_ext(&mut ext, 0x0010, &alpn_body);
    }

    ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    ch.extend_from_slice(&ext);
    wrap_handshake(HSType::ClientHello as u8, &ch)
}

fn push_ext(dst: &mut Vec<u8>, ty: u16, body: &[u8]) {
    dst.extend_from_slice(&ty.to_be_bytes());
    dst.extend_from_slice(&(body.len() as u16).to_be_bytes());
    dst.extend_from_slice(body);
}

fn parse_handshake_view(input: &[u8]) -> Result<(u8, &[u8], usize), OnionError> {
    if input.len() < 4 { return Err(OnionError::InvalidCell); }
    let typ = input[0];
    let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    if input.len() < 4 + len { return Err(OnionError::InvalidCell); }
    Ok((typ, &input[4..4 + len], 4 + len))
}

fn parse_server_hello(body: &[u8]) -> Result<(u16, [u8; 32], [u8; 32]), OnionError> {
    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 { return Err(OnionError::InvalidCell); }
    let mut off = 0usize;
    let legacy = u16::from_be_bytes([body[off], body[off + 1]]); off += 2;
    if legacy != TLS_1_2 { return Err(OnionError::CryptoError); }
    let mut random = [0u8; 32]; random.copy_from_slice(&body[off..off + 32]); off += 32;
    let sid_len = body[off] as usize; off += 1 + sid_len;
    let suite = u16::from_be_bytes([body[off], body[off + 1]]); off += 2;
    off += 1; // compression
    let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize; off += 2;
    if body.len() < off + ext_len { return Err(OnionError::InvalidCell); }
    let mut exts = &body[off..off + ext_len];

    let mut server_pub = [0u8; 32];
    let mut seen_sv = false;
    let mut seen_ks = false;

    while exts.len() >= 4 {
        let ety = u16::from_be_bytes([exts[0], exts[1]]);
        let el = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        if exts.len() < 4 + el { return Err(OnionError::InvalidCell); }
        let ebody = &exts[4..4 + el];

        match ety {
            0x002b => { // supported_versions(server)
                if el != 2 || u16::from_be_bytes([ebody[0], ebody[1]]) != TLS_1_3 { return Err(OnionError::CryptoError); }
                seen_sv = true;
            }
            0x0033 => { // key_share(server)
                if el < 4 { return Err(OnionError::CryptoError); }
                let _group = u16::from_be_bytes([ebody[0], ebody[1]]);
                let klen = u16::from_be_bytes([ebody[2], ebody[3]]) as usize;
                if klen != 32 || el < 4 + klen { return Err(OnionError::CryptoError); }
                server_pub.copy_from_slice(&ebody[4..4 + 32]);
                seen_ks = true;
            }
            _ => {}
        }
        exts = &exts[4 + el..];
    }

    if !(seen_sv && seen_ks) { return Err(OnionError::CryptoError); }
    Ok((suite, server_pub, random))
}

fn parse_certificate_chain(body: &[u8]) -> Result<Vec<Vec<u8>>, OnionError> {
    if body.len() < 1 + 3 { return Err(OnionError::InvalidCell); }
    let mut off = 0usize;
    let ctx_len = body[off] as usize; off += 1 + ctx_len;
    let list_len = ((body[off] as usize) << 16) | ((body[off + 1] as usize) << 8) | (body[off + 2] as usize);
    off += 3;
    if body.len() < off + list_len { return Err(OnionError::InvalidCell); }
    let mut certs = Vec::new();
    let mut cur = &body[off..off + list_len];
    while cur.len() >= 3 {
        let clen = ((cur[0] as usize) << 16) | ((cur[1] as usize) << 8) | (cur[2] as usize);
        if cur.len() < 3 + clen + 2 { break; }
        let der = &cur[3..3 + clen];
        certs.push(der.to_vec());
        let elen = u16::from_be_bytes([cur[3 + clen], cur[3 + clen + 1]]) as usize;
        if cur.len() < 3 + clen + 2 + elen { break; }
        cur = &cur[3 + clen + 2 + elen..];
    }
    Ok(certs)
}

fn parse_certificate_verify(body: &[u8]) -> Result<(u16, Vec<u8>), OnionError> {
    if body.len() < 4 { return Err(OnionError::InvalidCell); }
    let alg = u16::from_be_bytes([body[0], body[1]]);
    let sl = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sl { return Err(OnionError::InvalidCell); }
    Ok((alg, body[4..4 + sl].to_vec()))
}

/* ===== Finished and CV context ===== */

fn build_finished(secret: &Secret, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let finished_key = expand_label(&secret.secret, b"finished", &[]);
    let mut mac = [0u8; 32];
    crypto().hmac_sha256(&finished_key, transcript_hash, &mut mac);
    wrap_handshake(HSType::Finished as u8, &mac)
}

fn verify_finished_with_payload(secret: &Secret, transcript_hash: &[u8; 32], received_mac: &[u8]) -> bool {
    let finished_key = expand_label(&secret.secret, b"finished", &[]);
    let mut mac = [0u8; 32];
    crypto().hmac_sha256(&finished_key, transcript_hash, &mut mac);
    mac.as_slice() == received_mac
}

fn build_cert_verify_context(th: &[u8; 32]) -> Vec<u8> {
    // 64 bytes of 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
    let mut v = Vec::with_capacity(64 + 33 + th.len());
    v.extend_from_slice(&[0x20u8; 64]);
    v.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    v.push(0u8);
    v.extend_from_slice(th);
    v
}

/* ===== HKDF-Expand-Label (SHA-256) ===== */

fn expand_label(prk: &[u8; 32], label: &[u8], context: &[u8]) -> [u8; 32] {
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

/* ===== Record framing ===== */

fn wrap_handshake(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(typ);
    hs.push(((body.len() >> 16) & 0xFF) as u8);
    hs.push(((body.len() >> 8) & 0xFF) as u8);
    hs.push((body.len() & 0xFF) as u8);
    hs.extend_from_slice(body);
    hs
}

fn wrap_record(ct: u8, legacy_version: u16, body: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + body.len());
    rec.push(ct);
    rec.extend_from_slice(&legacy_version.to_be_bytes());
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}

/* ===== I/O helpers ===== */

fn write_all(sock: &TcpSocket, data: &[u8], timeout_ms: u64) -> Result<(), OnionError> {
    let start = time::timestamp_millis();
    if let Some(net) = get_network_stack() {
        let mut off = 0usize;
        while off < data.len() {
            if time::timestamp_millis().saturating_sub(start) > timeout_ms { return Err(OnionError::Timeout); }
            match net.tcp_send(sock.connection_id(), &data[off..]) {
                Ok(n) if n > 0 => off += n,
                Ok(_) => crate::time::yield_now(),
                Err(_) => return Err(OnionError::NetworkError),
            }
        }
        Ok(())
    } else { Err(OnionError::NetworkError) }
}

fn read_some(sock: &TcpSocket, dst: &mut [u8], timeout_ms: u64) -> Result<usize, OnionError> {
    let start = time::timestamp_millis();
    if let Some(net) = get_network_stack() {
        loop {
            if time::timestamp_millis().saturating_sub(start) > timeout_ms { return Err(OnionError::Timeout); }
            match net.tcp_receive(sock.connection_id(), dst.len()) {
                Ok(buf) if !buf.is_empty() => {
                    let n = min(dst.len(), buf.len());
                    dst[..n].copy_from_slice(&buf[..n]);
                    return Ok(n);
                }
                _ => crate::time::yield_now(),
            }
        }
    } else { Err(OnionError::NetworkError) }
}

/* ===== Backends: TLS crypto + X.509 verification ===== */

pub trait TlsCrypto: Sync + Send {
    /* Random */
    fn random(&self, out32: &mut [u8; 32]) -> Result<(), OnionError>;

    /* Hash/KDF/MAC (SHA-256 suites only) */
    fn sha256(&self, data: &[u8], out32: &mut [u8; 32]);
    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]);
    fn hkdf_extract(&self, salt: &[u8; 32], ikm: &[u8; 32], out32: &mut [u8; 32]);
    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]);

    /* ECDH */
    fn x25519_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError>;
    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError>;

    /* AEAD */
    fn aead_seal(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError>;

    fn aead_open(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OnionError>;

    /* Signature verification used by CertificateVerify */
    fn verify_ed25519(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_rsa_pss_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_ecdsa_p256_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

pub trait CertVerifier: Sync + Send {
    /// `chain_der` = leaf..ca (DER each). For Tor link TLS, require a single self-signed leaf.
    fn verify(&self, chain_der: &[Vec<u8>], sni: &str) -> Result<(), OnionError>;
}

/* Singletons */

use spin::Once;
static TLS_CRYPTO: Once<&'static dyn TlsCrypto> = Once::new();
static CERT_VERIFIER: Once<&'static dyn CertVerifier> = Once::new();

pub fn init_tls_crypto(provider: &'static dyn TlsCrypto) { TLS_CRYPTO.call_once(|| provider); }
pub fn init_tls_cert_verifier(v: &'static dyn CertVerifier) { CERT_VERIFIER.call_once(|| v); }

/// Production initialization
pub fn init_tls_stack_production(provider: &'static dyn TlsCrypto) -> Result<(), OnionError> {
    init_tls_crypto(provider);
    init_tls_cert_verifier(&STRICT_TOR_LINK_VERIFIER);
    Ok(())
}

#[inline]
fn crypto() -> &'static dyn TlsCrypto { *TLS_CRYPTO.get().expect("TlsCrypto not initialized") }

#[derive(Debug, Clone, PartialEq)]
pub enum TLSState { Start, Connected, Closed, Error }

pub use super::nonos_crypto::X509Certificate;

/* ===== Strict Tor link certificate verifier ===== */

struct StrictTorLinkVerifier;
static STRICT_TOR_LINK_VERIFIER: StrictTorLinkVerifier = StrictTorLinkVerifier;

impl CertVerifier for StrictTorLinkVerifier {
    fn verify(&self, chain_der: &[Vec<u8>], _sni: &str) -> Result<(), OnionError> {
        if chain_der.len() != 1 { return Err(OnionError::AuthenticationFailed); }
        let cert = X509::parse_der(&chain_der[0])?;
        // Basic checks consistent with Tor link usage
        X509::verify_self_signed(&cert)?;
        X509::check_basic_constraints_end_entity(&cert)?;
        X509::check_time_validity(&cert, crate::time::timestamp_millis())?;
        Ok(())
    }
}

/* ===== X.509 adapter ===== */

pub enum PublicKeyKind { Rsa, Ed25519, EcdsaP256 }

pub struct X509;
impl X509 {
    pub fn parse_der(der: &[u8]) -> Result<X509Certificate, OnionError> {
        super::nonos_crypto::X509::parse_der(der)
    }
    pub fn verify_self_signed(cert: &X509Certificate) -> Result<(), OnionError> {
        super::nonos_crypto::X509::verify_self_signed(cert)
    }
    pub fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
        super::nonos_crypto::X509::check_basic_constraints_end_entity(cert)
    }
    pub fn check_time_validity(cert: &X509Certificate, now_ms: u64) -> Result<(), OnionError> {
        super::nonos_crypto::X509::check_time_validity(cert, now_ms)
    }
    pub fn public_key_info(cert: &X509Certificate) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        super::nonos_crypto::X509::public_key_info(cert)
    }
}

/* ===== Misc helpers ===== */

fn has_tls12_downgrade_sentinel(random: &[u8; 32]) -> bool {
    // last 8 bytes equal to: 44 4F 57 4E 47 52 44 01 for TLS1.2 sentinel (RFC8446 S4.1.3)
    let s = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
    &random[24..32] == &s
}

/* ===== Kernel TLS crypto provider  ===== */

pub struct KernelTlsCrypto;
pub static KERNEL_TLS_CRYPTO: KernelTlsCrypto = KernelTlsCrypto;

impl TlsCrypto for KernelTlsCrypto {
    fn random(&self, out32: &mut [u8; 32]) -> Result<(), OnionError> {
        super::nonos_crypto::rand32(out32).map_err(|_| OnionError::CryptoError)
    }

    fn sha256(&self, data: &[u8], out32: &mut [u8; 32]) {
        super::nonos_crypto::sha256(data, out32)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]) {
        super::nonos_crypto::hmac_sha256(key, data, out32)
    }

    fn hkdf_extract(&self, salt: &[u8; 32], ikm: &[u8; 32], out32: &mut [u8; 32]) {
        super::nonos_crypto::hkdf_extract_sha256(salt, ikm, out32)
    }

    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
        super::nonos_crypto::hkdf_expand_sha256(prk, info, out)
    }

    fn x25519_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError> {
        super::nonos_crypto::x25519_keypair().map_err(|_| OnionError::CryptoError)
    }

    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError> {
        super::nonos_crypto::x25519(sk, pk).map_err(|_| OnionError::CryptoError)
    }

    fn aead_seal(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        match suite {
            CipherSuite::TlsAes128GcmSha256 => super::nonos_crypto::aes128_gcm_seal(key, nonce, aad, plaintext),
            CipherSuite::TlsChacha20Poly1305Sha256 => super::nonos_crypto::chacha20poly1305_seal(key, nonce, aad, plaintext),
        }.map_err(|_| OnionError::CryptoError)
    }

    fn aead_open(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        match suite {
            CipherSuite::TlsAes128GcmSha256 => super::nonos_crypto::aes128_gcm_open(key, nonce, aad, ciphertext),
            CipherSuite::TlsChacha20Poly1305Sha256 => super::nonos_crypto::chacha20poly1305_open(key, nonce, aad, ciphertext),
        }.map_err(|_| OnionError::CryptoError)
    }

    fn verify_ed25519(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        super::nonos_crypto::ed25519_verify(pubkey, msg, sig)
    }

    fn verify_rsa_pss_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        super::nonos_crypto::rsa_pss_sha256_verify_spki(spki_der, msg, sig)
    }

    fn verify_ecdsa_p256_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        super::nonos_crypto::ecdsa_p256_sha256_verify_spki(spki_der, msg, sig)
    }
}
