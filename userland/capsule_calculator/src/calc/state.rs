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

use super::op::Op;

pub struct State {
    pub display: i64,
    pub operand: i64,
    pub operator: Op,
    pub new_input: bool,
    pub decimal_pos: u8,
    pub error: bool,
}

impl State {
    pub fn new() -> Self {
        State {
            display: 0,
            operand: 0,
            operator: Op::None,
            new_input: true,
            decimal_pos: 0,
            error: false,
        }
    }
}
