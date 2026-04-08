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
use alloc::vec::Vec;

pub struct Tx1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority: u64,
    pub max_fee: u64,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

impl Tx1559 {
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        buf.push(0x02);
        self.rlp_encode(&mut buf);
        crate::crypto::keccak::keccak256(&buf)
    }

    pub fn sign(&self, privkey: &[u8; 32]) -> Vec<u8> {
        let hash = self.hash();
        let sig = crate::crypto::secp256k1::sign(&hash, privkey);
        let mut out = Vec::with_capacity(256);
        out.push(0x02);
        self.rlp_signed(&mut out, &sig);
        out
    }

    fn rlp_encode(&self, buf: &mut Vec<u8>) {
        let items: [&[u8]; 9] = [
            &trim(&self.chain_id.to_be_bytes()), &trim(&self.nonce.to_be_bytes()),
            &trim(&self.max_priority.to_be_bytes()), &trim(&self.max_fee.to_be_bytes()),
            &trim(&self.gas_limit.to_be_bytes()), &self.to,
            &trim(&self.value.to_be_bytes()), &self.data, &[],
        ];
        rlp_list(buf, &items);
    }

    fn rlp_signed(&self, buf: &mut Vec<u8>, sig: &[u8; 65]) {
        let v = [sig[64]];
        let r = trim(&sig[0..32]);
        let s = trim(&sig[32..64]);
        let items: [&[u8]; 12] = [
            &trim(&self.chain_id.to_be_bytes()), &trim(&self.nonce.to_be_bytes()),
            &trim(&self.max_priority.to_be_bytes()), &trim(&self.max_fee.to_be_bytes()),
            &trim(&self.gas_limit.to_be_bytes()), &self.to,
            &trim(&self.value.to_be_bytes()), &self.data, &[], &v, r, s,
        ];
        rlp_list(buf, &items);
    }
}

fn trim(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    if i == b.len() { &[] } else { &b[i..] }
}

fn rlp_list(buf: &mut Vec<u8>, items: &[&[u8]]) {
    let mut len = 0;
    for i in items.iter() { len += rlp_item_len(*i); }
    if len < 56 { buf.push(0xc0 + len as u8); }
    else { buf.push(0xf7 + len_size(len) as u8); push_len(buf, len); }
    for i in items.iter() { rlp_item(buf, *i); }
}

fn rlp_item(buf: &mut Vec<u8>, d: &[u8]) {
    if d.len() == 1 && d[0] < 0x80 { buf.push(d[0]); }
    else if d.len() < 56 { buf.push(0x80 + d.len() as u8); buf.extend_from_slice(d); }
    else { buf.push(0xb7 + len_size(d.len()) as u8); push_len(buf, d.len()); buf.extend_from_slice(d); }
}

fn rlp_item_len(d: &[u8]) -> usize {
    if d.len() == 1 && d[0] < 0x80 { 1 }
    else if d.len() < 56 { 1 + d.len() }
    else { 1 + len_size(d.len()) + d.len() }
}

fn len_size(n: usize) -> usize { if n < 256 { 1 } else if n < 65536 { 2 } else { 3 } }

fn push_len(buf: &mut Vec<u8>, n: usize) {
    let s = len_size(n);
    for i in (0..s).rev() { buf.push((n >> (i * 8)) as u8); }
}
