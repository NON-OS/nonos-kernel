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

use crate::protocol::{
    AEAD_KEY_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES, MAX_AEAD_AAD_BYTES, MAX_AEAD_PT_BYTES,
};

pub(super) const KEY_LEN: usize = AEAD_KEY_BYTES as usize;
pub(super) const NONCE_LEN: usize = AEAD_NONCE_BYTES as usize;
pub(super) const AAD_LEN_FIELD: usize = 4;
pub(super) const HEADER_LEN: usize = KEY_LEN + NONCE_LEN + AAD_LEN_FIELD;
pub(super) const MAX_AAD: usize = MAX_AEAD_AAD_BYTES as usize;
pub(super) const MAX_PT: usize = MAX_AEAD_PT_BYTES as usize;
pub(super) const TAG_LEN: usize = AEAD_TAG_BYTES as usize;
