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

#![no_std]
#![no_main]

use nonos_app_skeleton::{marker, run, App, Frame, WindowCfg};

const BG: u32 = 0xFF10_1822;
const FG: u32 = 0xFFE6_EDF3;
const ACCENT: u32 = 0xFF4C_9AFF;

struct About;

impl App for About {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 220, y: 160, width: 400, height: 220, z: 10 }
    }

    fn init(&mut self) {
        marker(b"[about] ", b"info shown");
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        f.text(24, 28, b"NONOS", ACCENT);
        f.text(24, 64, b"Plan A user surface", FG);
        f.text(24, 92, b"capsule_about v0.1", FG);
        f.text(24, 120, b"AGPL-3.0", FG);
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(b"[about] ", About)
}
