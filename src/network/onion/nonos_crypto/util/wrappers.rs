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

use crate::crypto::{entropy, hash};
use crate::network::onion::OnionError;

pub fn rand32(out: &mut [u8; 32]) -> Result<(), OnionError> {
    let entropy_bytes = entropy::get_entropy(32);
    out.copy_from_slice(&entropy_bytes[..32]);
    Ok(())
}

pub fn sha256(data: &[u8], out: &mut [u8; 32]) -> Result<(), OnionError> {
    let result = hash::sha256(data);
    out.copy_from_slice(&result);
    Ok(())
}
