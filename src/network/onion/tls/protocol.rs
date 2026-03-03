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
use super::types::{CipherSuite, HSType, TLS_1_2, TLS_1_3};
use super::keys::{expand_label, Secret};
use super::crypto_provider::crypto;

pub(super) fn build_client_hello(
    client_random: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    epk: &[u8; 32],
) -> Vec<u8> {
    let mut ch = Vec::with_capacity(512);
    ch.extend_from_slice(&TLS_1_2.to_be_bytes());
    ch.extend_from_slice(client_random);
    ch.push(0);

    let ciphers: [u16; 2] = [
        CipherSuite::TlsAes128GcmSha256 as u16,
        CipherSuite::TlsChacha20Poly1305Sha256 as u16,
    ];
    ch.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for cs in ciphers {
        ch.extend_from_slice(&cs.to_be_bytes());
    }
    ch.push(1);
    ch.push(0);

    let mut ext = Vec::with_capacity(256);

    {
        let mut body = Vec::new();
        body.push(2);
        body.extend_from_slice(&TLS_1_3.to_be_bytes());
        push_ext(&mut ext, 0x002b, &body);
    }

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

    {
        let sigs: [u16; 5] = [0x0403, 0x0804, 0x0805, 0x0806, 0x0807];
        let mut body = Vec::new();
        body.extend_from_slice(&((sigs.len() as u16) * 2).to_be_bytes());
        for s in sigs {
            body.extend_from_slice(&s.to_be_bytes());
        }
        push_ext(&mut ext, 0x000d, &body);
    }

    {
        let groups: [u16; 2] = [0x001d, 0x0017];
        let mut body = Vec::new();
        body.extend_from_slice(&((groups.len() as u16) * 2).to_be_bytes());
        for g in groups {
            body.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut ext, 0x000a, &body);
    }

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

    if let Some(protocols) = alpn {
        let mut alpn_body = Vec::new();
        let mut list = Vec::new();
        for p in protocols {
            let pb = p.as_bytes();
            if pb.len() > 255 {
                continue;
            }
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

pub(super) fn parse_handshake_view(input: &[u8]) -> Result<(u8, &[u8], usize), OnionError> {
    if input.len() < 4 {
        return Err(OnionError::InvalidCell);
    }
    let typ = input[0];
    let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    if input.len() < 4 + len {
        return Err(OnionError::InvalidCell);
    }
    Ok((typ, &input[4..4 + len], 4 + len))
}

pub(super) fn parse_server_hello(body: &[u8]) -> Result<(u16, [u8; 32], [u8; 32]), OnionError> {
    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        return Err(OnionError::InvalidCell);
    }
    let mut off = 0usize;
    let legacy = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 2;
    if legacy != TLS_1_2 {
        return Err(OnionError::CryptoError);
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[off..off + 32]);
    off += 32;
    let sid_len = body[off] as usize;
    off += 1 + sid_len;
    let suite = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 2;
    off += 1;
    let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ext_len {
        return Err(OnionError::InvalidCell);
    }
    let mut exts = &body[off..off + ext_len];

    let mut server_pub = [0u8; 32];
    let mut seen_sv = false;
    let mut seen_ks = false;

    while exts.len() >= 4 {
        let ety = u16::from_be_bytes([exts[0], exts[1]]);
        let el = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        if exts.len() < 4 + el {
            return Err(OnionError::InvalidCell);
        }
        let ebody = &exts[4..4 + el];

        match ety {
            0x002b => {
                if el != 2 || u16::from_be_bytes([ebody[0], ebody[1]]) != TLS_1_3 {
                    return Err(OnionError::CryptoError);
                }
                seen_sv = true;
            }
            0x0033 => {
                if el < 4 {
                    return Err(OnionError::CryptoError);
                }
                let klen = u16::from_be_bytes([ebody[2], ebody[3]]) as usize;
                if klen != 32 || el < 4 + klen {
                    return Err(OnionError::CryptoError);
                }
                server_pub.copy_from_slice(&ebody[4..4 + 32]);
                seen_ks = true;
            }
            _ => {}
        }
        exts = &exts[4 + el..];
    }

    if !(seen_sv && seen_ks) {
        return Err(OnionError::CryptoError);
    }
    Ok((suite, server_pub, random))
}

pub(super) fn parse_certificate_chain(body: &[u8]) -> Result<Vec<Vec<u8>>, OnionError> {
    if body.len() < 1 + 3 {
        return Err(OnionError::InvalidCell);
    }
    let mut off = 0usize;
    let ctx_len = body[off] as usize;
    off += 1 + ctx_len;
    let list_len = ((body[off] as usize) << 16) | ((body[off + 1] as usize) << 8) | (body[off + 2] as usize);
    off += 3;
    if body.len() < off + list_len {
        return Err(OnionError::InvalidCell);
    }
    let mut certs = Vec::new();
    let mut cur = &body[off..off + list_len];
    while cur.len() >= 3 {
        let clen = ((cur[0] as usize) << 16) | ((cur[1] as usize) << 8) | (cur[2] as usize);
        if cur.len() < 3 + clen + 2 {
            break;
        }
        let der = &cur[3..3 + clen];
        certs.push(der.to_vec());
        let elen = u16::from_be_bytes([cur[3 + clen], cur[3 + clen + 1]]) as usize;
        if cur.len() < 3 + clen + 2 + elen {
            break;
        }
        cur = &cur[3 + clen + 2 + elen..];
    }
    Ok(certs)
}

pub(super) fn parse_certificate_verify(body: &[u8]) -> Result<(u16, Vec<u8>), OnionError> {
    if body.len() < 4 {
        return Err(OnionError::InvalidCell);
    }
    let alg = u16::from_be_bytes([body[0], body[1]]);
    let sl = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sl {
        return Err(OnionError::InvalidCell);
    }
    Ok((alg, body[4..4 + sl].to_vec()))
}

pub(super) fn build_finished(secret: &Secret, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let finished_key = expand_label(&secret.secret, b"finished", &[]);
    let mut mac = [0u8; 32];
    crypto().hmac_sha256(&finished_key, transcript_hash, &mut mac);
    wrap_handshake(HSType::Finished as u8, &mac)
}

pub(super) fn verify_finished_with_payload(secret: &Secret, transcript_hash: &[u8; 32], received_mac: &[u8]) -> bool {
    let finished_key = expand_label(&secret.secret, b"finished", &[]);
    let mut mac = [0u8; 32];
    crypto().hmac_sha256(&finished_key, transcript_hash, &mut mac);
    mac.as_slice() == received_mac
}

pub(super) fn build_cert_verify_context(th: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + 33 + th.len());
    v.extend_from_slice(&[0x20u8; 64]);
    v.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    v.push(0u8);
    v.extend_from_slice(th);
    v
}

pub(super) fn wrap_handshake(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(typ);
    hs.push(((body.len() >> 16) & 0xFF) as u8);
    hs.push(((body.len() >> 8) & 0xFF) as u8);
    hs.push((body.len() & 0xFF) as u8);
    hs.extend_from_slice(body);
    hs
}

pub(super) fn wrap_record(ct: u8, legacy_version: u16, body: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + body.len());
    rec.push(ct);
    rec.extend_from_slice(&legacy_version.to_be_bytes());
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}

pub(super) fn has_tls12_downgrade_sentinel(random: &[u8; 32]) -> bool {
    let s = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
    &random[24..32] == &s
}
