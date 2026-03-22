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
use super::super::types::{CipherSuite, HSType, TLS_1_2, TLS_1_3};
use super::wrap::wrap_handshake;

pub fn build_client_hello(cr: &[u8; 32], sni: Option<&str>, alpn: Option<&[&str]>, epk: &[u8; 32]) -> Vec<u8> {
    let mut ch = Vec::with_capacity(512);
    ch.extend_from_slice(&TLS_1_2.to_be_bytes());
    ch.extend_from_slice(cr);
    ch.push(0);
    ch.extend_from_slice(&4u16.to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsAes128GcmSha256 as u16).to_be_bytes());
    ch.extend_from_slice(&(CipherSuite::TlsChacha20Poly1305Sha256 as u16).to_be_bytes());
    ch.push(1); ch.push(0);
    let mut ext = Vec::with_capacity(256);
    ext_push(&mut ext, 0x002b, &[2, (TLS_1_3 >> 8) as u8, TLS_1_3 as u8]);
    // SNI extension (RFC 6066 §3): ServerNameList { name_type(1) + name_len(2) + name }
    if let Some(h) = sni {
        let hb = h.as_bytes();
        let entry_len = (1 + 2 + hb.len()) as u16;
        let mut body = Vec::with_capacity(2 + entry_len as usize);
        body.extend_from_slice(&entry_len.to_be_bytes()); // ServerNameList length
        body.push(0); // name_type = host_name
        body.extend_from_slice(&(hb.len() as u16).to_be_bytes());
        body.extend_from_slice(hb);
        ext_push(&mut ext, 0x0000, &body);
    }
    let sigs: [u16; 4] = [0x0403, 0x0503, 0x0804, 0x0807];
    let mut sb = Vec::new(); sb.extend_from_slice(&8u16.to_be_bytes()); for s in sigs { sb.extend_from_slice(&s.to_be_bytes()); } ext_push(&mut ext, 0x000d, &sb);
    let mut gb = Vec::new(); gb.extend_from_slice(&2u16.to_be_bytes()); gb.extend_from_slice(&0x001d_u16.to_be_bytes()); ext_push(&mut ext, 0x000a, &gb);
    let mut ks = Vec::new(); ks.extend_from_slice(&0x001d_u16.to_be_bytes()); ks.extend_from_slice(&32u16.to_be_bytes()); ks.extend_from_slice(epk); let mut kb = Vec::new(); kb.extend_from_slice(&(ks.len() as u16).to_be_bytes()); kb.extend_from_slice(&ks); ext_push(&mut ext, 0x0033, &kb);
    if let Some(ps) = alpn { let mut l = Vec::new(); for p in ps { let pb = p.as_bytes(); if pb.len() < 256 { l.push(pb.len() as u8); l.extend_from_slice(pb); } } let mut ab = Vec::new(); ab.extend_from_slice(&(l.len() as u16).to_be_bytes()); ab.extend_from_slice(&l); ext_push(&mut ext, 0x0010, &ab); }
    ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    ch.extend_from_slice(&ext);
    wrap_handshake(HSType::ClientHello as u8, &ch)
}

fn ext_push(dst: &mut Vec<u8>, ty: u16, body: &[u8]) {
    dst.extend_from_slice(&ty.to_be_bytes());
    dst.extend_from_slice(&(body.len() as u16).to_be_bytes());
    dst.extend_from_slice(body);
}
