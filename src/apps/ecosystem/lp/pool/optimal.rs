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

pub fn calculate_optimal_token1_amount(
    token0_amount: u128,
    reserve0: u128,
    reserve1: u128,
) -> u128 {
    if reserve0 == 0 {
        return 0;
    }
    (token0_amount * reserve1) / reserve0
}

pub fn calculate_optimal_token0_amount(
    token1_amount: u128,
    reserve0: u128,
    reserve1: u128,
) -> u128 {
    if reserve1 == 0 {
        return 0;
    }
    (token1_amount * reserve0) / reserve1
}
