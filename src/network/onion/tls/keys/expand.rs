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

use super::super::crypto_provider::crypto;
use alloc::vec::Vec;

pub(super) fn expand_label_256(prk: &[u8; 32], label: &[u8], context: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    expand_label_len_256(prk, label, context, &mut out);
    out
}

fn expand_label_len_256(prk: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let mut full = Vec::new();
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    crypto().hkdf_expand(prk, &info, out);
}

pub(super) fn expand_label_384(prk: &[u8], label: &[u8], context: &[u8], hl: usize) -> [u8; 48] {
    let mut out = [0u8; 48];
    expand_label_into_384(prk, label, context, &mut out[..hl]);
    out
}

pub(super) fn expand_label_into_384(prk: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let mut full = Vec::new();
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    crypto().hkdf_expand_384(prk, &info, out);
}

pub(crate) fn expand_label(prk: &[u8], label: &[u8], context: &[u8], hash_len: usize) -> [u8; 48] {
    let mut out = [0u8; 48];
    expand_label_len(prk, label, context, &mut out[..hash_len], hash_len);
    out
}

pub(crate) fn expand_label_len(
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
    hash_len: usize,
) {
    if hash_len == 48 {
        expand_label_into_384(prk, label, context, out);
    } else {
        let mut prk32 = [0u8; 32];
        prk32[..prk.len().min(32)].copy_from_slice(&prk[..prk.len().min(32)]);
        expand_label_len_256(&prk32, label, context, out);
    }
}
