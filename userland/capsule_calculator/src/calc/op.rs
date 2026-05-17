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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Op {
    None,
    Add,
    Sub,
    Mul,
    Div,
}

pub fn apply(a: i64, b: i64, op: Op) -> i64 {
    match op {
        Op::None => b,
        Op::Add => a.saturating_add(b),
        Op::Sub => a.saturating_sub(b),
        Op::Mul => a.saturating_mul(b) / 100,
        Op::Div => {
            if b == 0 {
                0
            } else {
                a.saturating_mul(100) / b
            }
        }
    }
}
