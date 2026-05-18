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

use nonos_app_skeleton::PaintBuffer;

use super::format::u32_decimal;
use super::state::State;
use super::theme::{BACKGROUND, FOREGROUND, WARNING};

const TEXT_LEFT: u32 = 16;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    fb.text(TEXT_LEFT, 18, b"process_manager", FOREGROUND);
    fb.text(TEXT_LEFT, 56, b"kernel observability op: E_NOSYS", WARNING);
    fb.text(TEXT_LEFT, 80, b"(pending debug-gated syscall)", WARNING);
    let mut digits = [0u8; 10];
    let n = u32_decimal(state.refreshes, &mut digits);
    fb.text(TEXT_LEFT, 120, b"refreshes:", FOREGROUND);
    fb.text(TEXT_LEFT + 96, 120, &digits[..n], FOREGROUND);
}
