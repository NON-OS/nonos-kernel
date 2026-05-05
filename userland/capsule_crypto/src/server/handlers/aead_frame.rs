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

//! Canonical AEAD frame for both AES-256-GCM and ChaCha20-Poly1305.
//! The wire shape is fixed and identical for seal and open; the
//! per-op handler picks the cipher and decides whether the body is
//! plaintext or ciphertext+tag.
//!
//! ```text
//!   offset    field          size       constraint
//!   ------    ----------     ----       ----------
//!     0..32   key            32         exact
//!    32..44   nonce          12         exact
//!    44..48   aad_len (LE)   4          aad_len <= MAX_AEAD_AAD_BYTES (256)
//!    48..48+aad_len  aad     aad_len    raw bytes
//!    48+aad_len..end body    inferred   seal: <= MAX_AEAD_PT_BYTES
//!                                        open: TAG..=MAX_AEAD_PT_BYTES+TAG
//! ```
//!
//! There is no payload-length field on the wire; the body is
//! whatever follows the aad. "Trailing garbage" is not a separable
//! category — every byte after the aad belongs to the body. The op
//! caller bounds the body length per its own semantics (seal vs
//! open) before the cipher primitive sees the slice.
//!
//! Bounds enforcement uses `get(..)` rather than indexing or
//! `split_at` so a malformed length can never reach a panic site.
//! `aad_len` is folded through `checked_add` so a hostile aad_len
//! cannot wrap into a tiny body slice.

use crate::protocol::{
    AEAD_KEY_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES, MAX_AEAD_AAD_BYTES, MAX_AEAD_PT_BYTES,
};

const KEY_LEN: usize = AEAD_KEY_BYTES as usize;
const NONCE_LEN: usize = AEAD_NONCE_BYTES as usize;
const AAD_LEN_FIELD: usize = 4;
const HEADER_LEN: usize = KEY_LEN + NONCE_LEN + AAD_LEN_FIELD;
const MAX_AAD: usize = MAX_AEAD_AAD_BYTES as usize;
const MAX_PT: usize = MAX_AEAD_PT_BYTES as usize;
const TAG_LEN: usize = AEAD_TAG_BYTES as usize;

pub(super) struct SealFrame<'a> {
    pub key: &'a [u8],
    pub nonce: &'a [u8],
    pub aad: &'a [u8],
    pub plaintext: &'a [u8],
}

pub(super) struct OpenFrame<'a> {
    pub key: &'a [u8],
    pub nonce: &'a [u8],
    pub aad: &'a [u8],
    pub ciphertext: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameError {
    Short,
    OversizeAad,
    OversizePayload,
}

pub(super) fn parse_seal(payload: &[u8]) -> Result<SealFrame<'_>, FrameError> {
    let parts = parse_common(payload)?;
    if parts.body.len() > MAX_PT {
        return Err(FrameError::OversizePayload);
    }
    Ok(SealFrame { key: parts.key, nonce: parts.nonce, aad: parts.aad, plaintext: parts.body })
}

pub(super) fn parse_open(payload: &[u8]) -> Result<OpenFrame<'_>, FrameError> {
    let parts = parse_common(payload)?;
    if parts.body.len() < TAG_LEN {
        return Err(FrameError::Short);
    }
    if parts.body.len() > MAX_PT + TAG_LEN {
        return Err(FrameError::OversizePayload);
    }
    Ok(OpenFrame { key: parts.key, nonce: parts.nonce, aad: parts.aad, ciphertext: parts.body })
}

struct CommonParts<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    aad: &'a [u8],
    body: &'a [u8],
}

fn parse_common(payload: &[u8]) -> Result<CommonParts<'_>, FrameError> {
    let key = payload.get(0..KEY_LEN).ok_or(FrameError::Short)?;
    let nonce = payload.get(KEY_LEN..KEY_LEN + NONCE_LEN).ok_or(FrameError::Short)?;
    let aad_len_bytes = payload
        .get(KEY_LEN + NONCE_LEN..HEADER_LEN)
        .ok_or(FrameError::Short)?;
    let aad_len = u32::from_le_bytes([
        aad_len_bytes[0],
        aad_len_bytes[1],
        aad_len_bytes[2],
        aad_len_bytes[3],
    ]) as usize;
    if aad_len > MAX_AAD {
        return Err(FrameError::OversizeAad);
    }
    let aad_end = HEADER_LEN.checked_add(aad_len).ok_or(FrameError::OversizeAad)?;
    let aad = payload.get(HEADER_LEN..aad_end).ok_or(FrameError::Short)?;
    let body = payload.get(aad_end..).ok_or(FrameError::Short)?;
    Ok(CommonParts { key, nonce, aad, body })
}

// The userland workspace uses `panic = "abort"` and is no_std, so
// `cargo test` cannot link host-side unit tests against this parser.
// End-to-end exercise comes from `tests/boot/crypto_hash_round_trip.sh`
// which boots the kernel under QEMU and drives every AEAD op through
// this parser via the IPC round-trip; malformed frames there return
// the documented status without ever reaching the cipher primitive.
