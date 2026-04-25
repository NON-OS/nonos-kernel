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

use crate::zk_engine::circuit::{Circuit, CircuitBuilder, LinearCombination};
use crate::zk_engine::ZKError;

pub(super) fn build_stealth_spend_circuit() -> Result<Circuit, ZKError> {
    let mut b = CircuitBuilder::new();
    let stealth = b.alloc_input(Some("stealth_address"));
    let spend_com = b.alloc_input(Some("spend_pubkey_commitment"));
    let spend_sec = b.alloc_variable(Some("spend_secret"));
    let view_sec = b.alloc_variable(Some("view_secret"));
    let eph_sec = b.alloc_variable(Some("ephemeral_secret"));
    let shared = b.alloc_variable(Some("shared_secret"));
    b.enforce_multiplication(view_sec, eph_sec, shared);
    let derived = b.alloc_variable(Some("stealth_derived"));
    b.enforce_multiplication(spend_sec, shared, derived);
    b.enforce_equal(
        LinearCombination::from_variable(derived),
        LinearCombination::from_variable(stealth),
    );
    let com_int = b.alloc_variable(Some("commitment_intermediate"));
    b.enforce_multiplication(spend_sec, spend_sec, com_int);
    b.enforce_equal(
        LinearCombination::from_variable(com_int),
        LinearCombination::from_variable(spend_com),
    );
    b.build(6)
}
