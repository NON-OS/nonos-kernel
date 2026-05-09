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

//! Drives the canonical encoder in `nonos_marketplace_abi` and
//! threads the operator key through. Output is deterministic for a
//! given (input, key, serial) triple — the encoder is purely
//! structural and the signing closure is passed an exact
//! signed-bytes range.

use nonos_marketplace_abi::{encode_and_sign, MarketplaceIndex};

use crate::keys::OperatorKey;

pub fn sign_index(index: MarketplaceIndex, key: &OperatorKey) -> Vec<u8> {
    let (blob, _signature) = encode_and_sign(index, |signed_bytes| key.sign(signed_bytes));
    blob
}
