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

use super::super::types::{CipherSuite, HSType, TLS_1_2, TLS_1_3};
use super::wrap::wrap_handshake;
use alloc::vec::Vec;

/// PSK parameters for session resumption.
pub struct PskParams<'a> {
    pub ticket: &'a [u8],
    pub obfuscated_age: u32,
    pub binder_len: usize,
}

/// Build the initial ClientHello with X25519 + P-256 dual key shares.
/// Sending both eliminates the HelloRetryRequest round trip for P-256 servers.
pub fn build_client_hello(
    cr: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    key_shares: &[(u16, &[u8])],
) -> Vec<u8> {
    crate::sys::serial::println(b"[CH] build_client_hello called");
    let result = build_client_hello_inner(cr, sni, alpn, key_shares, None, None);
    crate::sys::serial::println(b"[CH] build_client_hello returning");
    result
}

/// Build a ClientHello2 (after HelloRetryRequest) with the requested key share
/// group and optional cookie from the server.
pub fn build_client_hello_retry(
    cr: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    key_shares: &[(u16, &[u8])],
    cookie: Option<&[u8]>,
) -> Vec<u8> {
    build_client_hello_inner(cr, sni, alpn, key_shares, cookie, None)
}

/// Build a ClientHello with PSK extension for session resumption.
/// Returns (full_message, binder_offset) where binder_offset is the position
/// within the returned message where the binder value starts (to be overwritten
/// after computing the binder HMAC over the truncated transcript).
pub fn build_client_hello_with_psk(
    cr: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    key_shares: &[(u16, &[u8])],
    psk: &PskParams<'_>,
) -> (Vec<u8>, usize) {
    build_client_hello_inner_psk(cr, sni, alpn, key_shares, psk)
}

fn build_client_hello_inner(
    cr: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    key_shares: &[(u16, &[u8])],
    cookie: Option<&[u8]>,
    _psk: Option<()>, // reserved for future use
) -> Vec<u8> {
    crate::sys::serial::println(b"[CH] enter");
    let mut ch = Vec::with_capacity(512);
    crate::sys::serial::println(b"[CH] ch alloc ok");
    ch.extend_from_slice(&TLS_1_2.to_be_bytes());
    ch.extend_from_slice(cr);
    ch.push(0);
    ch.extend_from_slice(&6u16.to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsAes128GcmSha256 as u16).to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsAes256GcmSha384 as u16).to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsChacha20Poly1305Sha256 as u16).to_be_bytes());
    ch.push(1);
    ch.push(0);
    let mut ext = Vec::with_capacity(256);
    ext_push(&mut ext, 0x002b, &[2, (TLS_1_3 >> 8) as u8, TLS_1_3 as u8]);
    // SNI extension (RFC 6066 §3)
    if let Some(h) = sni {
        let hb = h.as_bytes();
        let entry_len = (1 + 2 + hb.len()) as u16;
        let mut body = Vec::with_capacity(2 + entry_len as usize);
        body.extend_from_slice(&entry_len.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(hb.len() as u16).to_be_bytes());
        body.extend_from_slice(hb);
        ext_push(&mut ext, 0x0000, &body);
    }
    let sigs: [u16; 7] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0807, 0x0401, 0x0501];
    let mut sb = Vec::new();
    sb.extend_from_slice(&((sigs.len() * 2) as u16).to_be_bytes());
    for s in sigs {
        sb.extend_from_slice(&s.to_be_bytes());
    }
    ext_push(&mut ext, 0x000d, &sb);
    // supported_groups: X25519 (preferred) + secp256r1
    let groups: [u16; 2] = [0x001d, 0x0017];
    let mut gb = Vec::new();
    gb.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        gb.extend_from_slice(&g.to_be_bytes());
    }
    ext_push(&mut ext, 0x000a, &gb);
    // key_share extension: one or more KeyShareEntry
    let mut ks = Vec::new();
    for &(group, key_data) in key_shares {
        ks.extend_from_slice(&group.to_be_bytes());
        ks.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
        ks.extend_from_slice(key_data);
    }
    let mut kb = Vec::new();
    kb.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    kb.extend_from_slice(&ks);
    ext_push(&mut ext, 0x0033, &kb);
    // ALPN extension
    if let Some(ps) = alpn {
        let mut l = Vec::new();
        for p in ps {
            let pb = p.as_bytes();
            if pb.len() < 256 {
                l.push(pb.len() as u8);
                l.extend_from_slice(pb);
            }
        }
        let mut ab = Vec::new();
        ab.extend_from_slice(&(l.len() as u16).to_be_bytes());
        ab.extend_from_slice(&l);
        ext_push(&mut ext, 0x0010, &ab);
    }
    // Cookie extension (for HRR response, RFC 8446 §4.2.2)
    if let Some(cookie_data) = cookie {
        let mut cb = Vec::new();
        cb.extend_from_slice(&(cookie_data.len() as u16).to_be_bytes());
        cb.extend_from_slice(cookie_data);
        ext_push(&mut ext, 0x002c, &cb);
    }
    crate::sys::serial::println(b"[CH] ext done, wrapping");
    ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    ch.extend_from_slice(&ext);
    crate::sys::serial::println(b"[CH] calling wrap_handshake");
    wrap_handshake(HSType::ClientHello as u8, &ch)
}

fn ext_push(dst: &mut Vec<u8>, ty: u16, body: &[u8]) {
    dst.extend_from_slice(&ty.to_be_bytes());
    dst.extend_from_slice(&(body.len() as u16).to_be_bytes());
    dst.extend_from_slice(body);
}

/// Build extensions common to all ClientHello variants (before PSK).
fn build_common_extensions(
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    key_shares: &[(u16, &[u8])],
    cookie: Option<&[u8]>,
) -> Vec<u8> {
    let mut ext = Vec::with_capacity(256);
    ext_push(&mut ext, 0x002b, &[2, (TLS_1_3 >> 8) as u8, TLS_1_3 as u8]);
    if let Some(h) = sni {
        let hb = h.as_bytes();
        let entry_len = (1 + 2 + hb.len()) as u16;
        let mut body = Vec::with_capacity(2 + entry_len as usize);
        body.extend_from_slice(&entry_len.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(hb.len() as u16).to_be_bytes());
        body.extend_from_slice(hb);
        ext_push(&mut ext, 0x0000, &body);
    }
    let sigs: [u16; 7] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0807, 0x0401, 0x0501];
    let mut sb = Vec::new();
    sb.extend_from_slice(&((sigs.len() * 2) as u16).to_be_bytes());
    for s in sigs {
        sb.extend_from_slice(&s.to_be_bytes());
    }
    ext_push(&mut ext, 0x000d, &sb);
    let groups: [u16; 2] = [0x001d, 0x0017];
    let mut gb = Vec::new();
    gb.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        gb.extend_from_slice(&g.to_be_bytes());
    }
    ext_push(&mut ext, 0x000a, &gb);
    let mut ks = Vec::new();
    for &(group, key_data) in key_shares {
        ks.extend_from_slice(&group.to_be_bytes());
        ks.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
        ks.extend_from_slice(key_data);
    }
    let mut kb = Vec::new();
    kb.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    kb.extend_from_slice(&ks);
    ext_push(&mut ext, 0x0033, &kb);
    if let Some(ps) = alpn {
        let mut l = Vec::new();
        for p in ps {
            let pb = p.as_bytes();
            if pb.len() < 256 {
                l.push(pb.len() as u8);
                l.extend_from_slice(pb);
            }
        }
        let mut ab = Vec::new();
        ab.extend_from_slice(&(l.len() as u16).to_be_bytes());
        ab.extend_from_slice(&l);
        ext_push(&mut ext, 0x0010, &ab);
    }
    if let Some(cookie_data) = cookie {
        let mut cb = Vec::new();
        cb.extend_from_slice(&(cookie_data.len() as u16).to_be_bytes());
        cb.extend_from_slice(cookie_data);
        ext_push(&mut ext, 0x002c, &cb);
    }
    ext
}

/// Build a ClientHello with PSK extension as the last extension.
/// Returns (full_handshake_message, binder_offset_within_message).
///
/// The binder at `binder_offset..binder_offset+binder_len` is filled with zeros
/// and must be overwritten by the caller after computing the binder HMAC over
/// the truncated transcript (everything up to but not including the binder values).
fn build_client_hello_inner_psk(
    cr: &[u8; 32],
    sni: Option<&str>,
    alpn: Option<&[&str]>,
    key_shares: &[(u16, &[u8])],
    psk: &PskParams<'_>,
) -> (Vec<u8>, usize) {
    let mut ch = Vec::with_capacity(512);
    ch.extend_from_slice(&TLS_1_2.to_be_bytes());
    ch.extend_from_slice(cr);
    ch.push(0);
    ch.extend_from_slice(&6u16.to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsAes128GcmSha256 as u16).to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsAes256GcmSha384 as u16).to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsChacha20Poly1305Sha256 as u16).to_be_bytes());
    ch.push(1);
    ch.push(0);

    let mut ext = build_common_extensions(sni, alpn, key_shares, None);

    // psk_key_exchange_modes (MUST appear before pre_shared_key)
    ext_push(&mut ext, 0x002d, &[1, 0x01]); // psk_dhe_ke

    // pre_shared_key extension (RFC 8446 §4.2.11) — MUST be last extension
    // Build identities: identity_len(2) + identity + obfuscated_age(4)
    let mut identities = Vec::new();
    identities.extend_from_slice(&(psk.ticket.len() as u16).to_be_bytes());
    identities.extend_from_slice(psk.ticket);
    identities.extend_from_slice(&psk.obfuscated_age.to_be_bytes());

    // Build binders: binder_len(1) + binder(binder_len) — placeholder zeros
    let mut binders = Vec::new();
    binders.push(psk.binder_len as u8);
    binders.extend_from_slice(&vec![0u8; psk.binder_len]);

    // pre_shared_key body: identities_len(2) + identities + binders_len(2) + binders
    let mut psk_body = Vec::new();
    psk_body.extend_from_slice(&(identities.len() as u16).to_be_bytes());
    psk_body.extend_from_slice(&identities);
    psk_body.extend_from_slice(&(binders.len() as u16).to_be_bytes());
    psk_body.extend_from_slice(&binders);

    ext_push(&mut ext, 0x0029, &psk_body);

    ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    ch.extend_from_slice(&ext);

    let msg = wrap_handshake(HSType::ClientHello as u8, &ch);

    // Calculate binder offset within the final message.
    // The binder value starts at: msg.len() - binder_len
    let binder_offset = msg.len() - psk.binder_len;

    (msg, binder_offset)
}
