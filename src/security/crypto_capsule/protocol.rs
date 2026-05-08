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

// Kernel-side mirror of `userland/capsule_crypto/src/protocol/*`.
// Bit-for-bit identical layout — drift surfaces as
// `CryptoCapsuleError::ProtocolMismatch`.

use alloc::vec::Vec;

use crate::services::lifecycle::transport;

pub(super) const MAGIC: u32 = 0x4E4F_4358; // "NOCX"
pub(super) const VERSION: u16 = 1;

pub(super) const OP_BLAKE3_HASH: u16 = 1;
pub(super) const OP_SHA3_256_HASH: u16 = 2;
pub(super) const OP_HEALTHCHECK: u16 = 3;
pub(super) const OP_SHA256_HASH: u16 = 4;
pub(super) const OP_SHA512_HASH: u16 = 5;
pub(super) const OP_ED25519_VERIFY: u16 = 6;
pub(super) const OP_CHACHA20_POLY1305_SEAL: u16 = 10;
pub(super) const OP_CHACHA20_POLY1305_OPEN: u16 = 11;
pub(super) const OP_AES256_GCM_SEAL: u16 = 12;
pub(super) const OP_AES256_GCM_OPEN: u16 = 13;

pub(super) const ED25519_PUBKEY_BYTES: u32 = 32;
pub(super) const ED25519_SIG_BYTES: u32 = 64;
pub(super) const ED25519_HEADER_BYTES: u32 = ED25519_PUBKEY_BYTES + ED25519_SIG_BYTES;
pub(super) const MAX_VERIFY_MESSAGE_BYTES: u32 = 1024 * 1024;

pub(super) const MAX_INPUT_BYTES: u32 = 65536;
pub(super) const MAX_AEAD_PT_BYTES: u32 = 1024 * 1024;
pub(super) const MAX_AEAD_AAD_BYTES: u32 = 256;
pub(super) const AEAD_KEY_BYTES: u32 = 32;
pub(super) const AEAD_NONCE_BYTES: u32 = 12;
pub(super) const AEAD_TAG_BYTES: u32 = 16;
pub(super) const AEAD_HEADER_BYTES: u32 = AEAD_KEY_BYTES + AEAD_NONCE_BYTES + 4;
// Shared envelope budget — max of the AEAD plaintext path and
// the Ed25519 verify path so a single transport allocation
// covers both ops.
pub(super) const MAX_PAYLOAD_BYTES: u32 = {
    let aead = AEAD_HEADER_BYTES + MAX_AEAD_AAD_BYTES + MAX_AEAD_PT_BYTES + AEAD_TAG_BYTES;
    let verify = ED25519_HEADER_BYTES + MAX_VERIFY_MESSAGE_BYTES;
    if aead > verify {
        aead
    } else {
        verify
    }
};

pub(super) const KERNEL_REPLY_ENDPOINT: u64 = 0x1_0000_0004;

pub(super) use crate::services::lifecycle::transport::DecodedResponse;

pub(super) fn encode_request(op: u16, flags: u16, request_id: u32, body: &[u8]) -> Vec<u8> {
    transport::encode_request(MAGIC, VERSION, op, flags, request_id, body)
}

pub(super) fn decode_response(buf: &[u8]) -> Option<DecodedResponse<'_>> {
    transport::decode_v1_response(buf, MAGIC, VERSION, MAX_PAYLOAD_BYTES)
}
