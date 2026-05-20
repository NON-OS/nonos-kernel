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

use super::types::{Argv, MAX_ARGS};
use crate::term::util::is_space;

pub fn parse(input: &[u8]) -> Argv<'_> {
    let mut out = Argv { argv: [b""; MAX_ARGS], argc: 0 };
    let mut i = 0;
    while i < input.len() && out.argc < MAX_ARGS {
        while i < input.len() && is_space(input[i]) {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        let start = i;
        while i < input.len() && !is_space(input[i]) {
            i += 1;
        }
        out.argv[out.argc] = &input[start..i];
        out.argc += 1;
    }
    out
}
