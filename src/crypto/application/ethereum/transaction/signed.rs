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
use alloc::vec;
use alloc::vec::Vec;

use super::super::rlp::{rlp_encode_bytes, rlp_encode_list, rlp_encode_u128, rlp_encode_u64, trim_leading_zeros};
use super::super::HEX_CHARS;
use super::types::SignedTransaction;

impl SignedTransaction {
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut items = Vec::new();
        items.push(rlp_encode_u64(self.tx.nonce));
        items.push(rlp_encode_u128(self.tx.gas_price));
        items.push(rlp_encode_u64(self.tx.gas_limit));
        items.push(match &self.tx.to {
            Some(addr) => rlp_encode_bytes(&addr.0),
            None => vec![0x80],
        });
        items.push(rlp_encode_u128(self.tx.value));
        items.push(rlp_encode_bytes(&self.tx.data));
        items.push(rlp_encode_u64(self.v));
        items.push(rlp_encode_bytes(trim_leading_zeros(&self.r)));
        items.push(rlp_encode_bytes(trim_leading_zeros(&self.s)));
        rlp_encode_list(&items)
    }

    pub fn to_hex(&self) -> Vec<u8> {
        let raw = self.rlp_encode();
        let mut hex = Vec::with_capacity(2 + raw.len() * 2);
        hex.push(b'0');
        hex.push(b'x');
        for byte in raw {
            hex.push(HEX_CHARS[(byte >> 4) as usize]);
            hex.push(HEX_CHARS[(byte & 0x0f) as usize]);
        }
        hex
    }
}
