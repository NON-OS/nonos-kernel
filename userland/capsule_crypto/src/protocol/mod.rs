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

mod decode;
mod encode;
mod errno;
mod types;

pub use decode::decode_request;
pub use encode::encode_response;
pub use errno::{EACCES, EBADMSG, EINVAL, EIO, EMSGSIZE};
pub use types::{
    Request, AEAD_HEADER_BYTES, AEAD_KEY_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES,
    ED25519_HEADER_BYTES, ED25519_PUBKEY_BYTES, ED25519_SIG_BYTES, HDR_LEN, KERNEL_REPLY_ENDPOINT,
    MAGIC, MAX_AEAD_AAD_BYTES, MAX_AEAD_PT_BYTES, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES,
    MAX_PAYLOAD_BYTES, MAX_VERIFY_MESSAGE_BYTES, OP_AES256_GCM_OPEN, OP_AES256_GCM_SEAL,
    OP_BLAKE3_HASH, OP_CHACHA20_POLY1305_OPEN, OP_CHACHA20_POLY1305_SEAL, OP_ED25519_VERIFY,
    OP_HEALTHCHECK, OP_SHA256_HASH, OP_SHA3_256_HASH, OP_SHA512_HASH, VERSION,
};
