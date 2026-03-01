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

use super::ibpb::ibpb;

#[inline(never)]
pub fn rsb_fill() {
    // SAFETY: RSB filling sequence uses call instructions to push return addresses.
    unsafe {
        core::arch::asm!(
            "call 20f",
            "20: call 21f",
            "21: call 22f",
            "22: call 23f",
            "23: call 24f",
            "24: call 25f",
            "25: call 26f",
            "26: call 27f",
            "27: call 28f",
            "28: call 29f",
            "29: call 30f",
            "30: call 31f",
            "31: call 32f",
            "32: call 33f",
            "33: call 34f",
            "34: call 35f",
            "35: call 36f",
            "36: call 37f",
            "37: call 38f",
            "38: call 39f",
            "39: call 40f",
            "40: call 41f",
            "41: call 42f",
            "42: call 43f",
            "43: call 44f",
            "44: call 45f",
            "45: call 46f",
            "46: call 47f",
            "47: call 48f",
            "48: call 49f",
            "49: call 50f",
            "50: call 51f",
            "51:",
            "add rsp, 256",
            "lfence",
            options(nomem, preserves_flags)
        );
    }
}

#[inline(always)]
pub fn rsb_clear() {
    ibpb();
}
