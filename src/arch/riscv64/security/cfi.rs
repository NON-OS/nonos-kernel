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

// Zicfiss / Zicfilp detection lives behind a CSR probe that does not
// exist in the kernel yet (no SBI exposure, no DTB binding). The local
// has_zicfiss / has_zicfilp helpers return false until that lands.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfiMode {
    Disabled,
    ShadowStack,
    LandingPad,
    Both,
}

pub fn init_cfi() {
    if has_zicfiss() {
        enable_shadow_stack();
    }

    if has_zicfilp() {
        enable_landing_pad();
    }
}

fn has_zicfiss() -> bool {
    false
}

fn has_zicfilp() -> bool {
    false
}

fn enable_shadow_stack() {}

fn enable_landing_pad() {}

pub fn cfi_supported() -> bool {
    has_zicfiss() || has_zicfilp()
}

pub fn current_mode() -> CfiMode {
    let ss = has_zicfiss();
    let lp = has_zicfilp();

    match (ss, lp) {
        (false, false) => CfiMode::Disabled,
        (true, false) => CfiMode::ShadowStack,
        (false, true) => CfiMode::LandingPad,
        (true, true) => CfiMode::Both,
    }
}

pub fn software_shadow_stack_push(ra: usize) {
    let _ = ra;
}

pub fn software_shadow_stack_pop() -> usize {
    0
}

pub fn software_shadow_stack_check(expected: usize, actual: usize) -> bool {
    expected == actual
}
