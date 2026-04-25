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

pub(super) fn pkcs1_digest_info_sha256(hash: &[u8]) -> Vec<u8> {
    let sha256_oid = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut di = Vec::with_capacity(sha256_oid.len() + hash.len());
    di.extend_from_slice(&sha256_oid);
    di.extend_from_slice(hash);
    di
}

pub(super) fn pkcs1_digest_info_sha256_no_null(hash: &[u8]) -> Vec<u8> {
    let sha256_oid_no_null = [
        0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x04, 0x20,
    ];
    let mut di = Vec::with_capacity(sha256_oid_no_null.len() + hash.len());
    di.extend_from_slice(&sha256_oid_no_null);
    di.extend_from_slice(hash);
    di
}

pub(super) fn pkcs1_digest_info_sha384(hash: &[u8]) -> Vec<u8> {
    let prefix = [
        0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    let mut di = Vec::with_capacity(prefix.len() + hash.len());
    di.extend_from_slice(&prefix);
    di.extend_from_slice(hash);
    di
}

pub(super) fn pkcs1_digest_info_sha384_no_null(hash: &[u8]) -> Vec<u8> {
    let prefix = [
        0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x04, 0x30,
    ];
    let mut di = Vec::with_capacity(prefix.len() + hash.len());
    di.extend_from_slice(&prefix);
    di.extend_from_slice(hash);
    di
}

pub(super) fn pkcs1_digest_info_sha512(hash: &[u8]) -> Vec<u8> {
    let prefix = [
        0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    let mut di = Vec::with_capacity(prefix.len() + hash.len());
    di.extend_from_slice(&prefix);
    di.extend_from_slice(hash);
    di
}

pub(super) fn pkcs1_digest_info_sha512_no_null(hash: &[u8]) -> Vec<u8> {
    let prefix = [
        0x30, 0x4F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x04, 0x40,
    ];
    let mut di = Vec::with_capacity(prefix.len() + hash.len());
    di.extend_from_slice(&prefix);
    di.extend_from_slice(hash);
    di
}
