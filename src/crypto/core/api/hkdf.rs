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

pub fn hkdf_expand_labeled(
    prk: &crate::crypto::hash::Hash256,
    label: &[u8],
    context: &[u8],
    okm: &mut [u8]
) -> Result<(), crate::crypto::CryptoError> {
    let mut info = Vec::with_capacity(label.len() + context.len());
    info.extend_from_slice(label);
    info.extend_from_slice(context);
    crate::crypto::hash::hkdf_expand(prk, &info, okm).map_err(|_| crate::crypto::CryptoError::InvalidLength)
}
