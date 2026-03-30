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

use alloc::vec::Vec;

pub fn deserialize_constraints(
    data: &[u8],
) -> Result<Vec<crate::zk_engine::circuit::Constraint>, &'static str> {
    if data.len() % 64 != 0 {
        return Err("Invalid constraints format");
    }

    let num_constraints = data.len() / 64;
    let mut constraints = Vec::with_capacity(num_constraints);

    for i in 0..num_constraints {
        let constraint = crate::zk_engine::circuit::Constraint::default_multiplication(i);
        constraints.push(constraint);
    }

    Ok(constraints)
}
