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

use nonos_app_skeleton::{marker, run, App, Frame, InputEvent, WindowCfg, KIND_KEY_DOWN};

const BG: u32 = 0xFF14_1A1F;
const FG: u32 = 0xFFDD_E6EC;
const SEL: u32 = 0xFF6C_E08C;
const LABELS: [&[u8]; 4] = [b"dark mode", b"animations", b"sounds", b"telemetry"];

struct Settings {
    on: [bool; 4],
    sel: usize,
}

impl App for Settings {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 250, y: 170, width: 380, height: 260, z: 10 }
    }

    fn on_input(&mut self, ev: InputEvent) -> bool {
        if ev.kind != KIND_KEY_DOWN {
            return false;
        }
        match ev.code as u8 {
            b'j' => self.sel = (self.sel + 1) % LABELS.len(),
            b'k' => self.sel = (self.sel + LABELS.len() - 1) % LABELS.len(),
            b' ' | 13 => {
                self.on[self.sel] = !self.on[self.sel];
                marker(
                    b"[settings] toggled ",
                    if self.on[self.sel] { b"on" } else { b"off" },
                );
            }
            _ => return false,
        }
        true
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        f.text(16, 18, b"settings", FG);
        let mut y = 56;
        for (i, l) in LABELS.iter().enumerate() {
            let mark: &[u8] = if self.on[i] { b"[x] " } else { b"[ ] " };
            let color = if i == self.sel { SEL } else { FG };
            f.text(20, y, mark, color);
            f.text(60, y, l, color);
            y += 26;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(b"[settings] ", Settings { on: [false; 4], sel: 0 })
}
