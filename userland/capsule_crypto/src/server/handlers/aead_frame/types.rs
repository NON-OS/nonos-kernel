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

pub(super) struct SealFrame<'a> {
    pub(super) key: &'a [u8],
    pub(super) nonce: &'a [u8],
    pub(super) aad: &'a [u8],
    pub(super) plaintext: &'a [u8],
}

pub(super) struct OpenFrame<'a> {
    pub(super) key: &'a [u8],
    pub(super) nonce: &'a [u8],
    pub(super) aad: &'a [u8],
    pub(super) ciphertext: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameError {
    Short,
    OversizeAad,
    OversizePayload,
}

pub(super) struct CommonParts<'a> {
    pub(super) key: &'a [u8],
    pub(super) nonce: &'a [u8],
    pub(super) aad: &'a [u8],
    pub(super) body: &'a [u8],
}
