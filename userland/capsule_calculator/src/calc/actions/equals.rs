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

use crate::calc::op::{apply, Op};
use crate::calc::state::State;

pub fn equals(state: &mut State) {
    if state.error || state.operator == Op::None {
        return;
    }
    if state.operator == Op::Div && state.display == 0 {
        state.error = true;
        state.display = 0;
    } else {
        state.display = apply(state.operand, state.display, state.operator);
    }
    state.operator = Op::None;
    state.new_input = true;
    state.decimal_pos = 0;
}
