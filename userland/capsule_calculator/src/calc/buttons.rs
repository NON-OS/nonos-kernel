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

#[derive(Clone, Copy)]
pub enum Role {
    Function,
    Number,
    Operator,
    Equals,
}

pub struct Button {
    pub label: &'static [u8],
    pub role: Role,
}

const fn b(label: &'static [u8], role: Role) -> Button {
    Button { label, role }
}

pub static GRID: [[Button; 4]; 5] = [
    [b(b"AC", Role::Function), b(b"+/-", Role::Function), b(b"%", Role::Function), b(b"/", Role::Operator)],
    [b(b"7", Role::Number), b(b"8", Role::Number), b(b"9", Role::Number), b(b"*", Role::Operator)],
    [b(b"4", Role::Number), b(b"5", Role::Number), b(b"6", Role::Number), b(b"-", Role::Operator)],
    [b(b"1", Role::Number), b(b"2", Role::Number), b(b"3", Role::Number), b(b"+", Role::Operator)],
    [b(b"0", Role::Number), b(b".", Role::Number), b(b"C", Role::Function), b(b"=", Role::Equals)],
];
