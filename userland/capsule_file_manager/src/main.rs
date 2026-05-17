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

const BG: u32 = 0xFF12_1622;
const FG: u32 = 0xFFD7_E2F2;
const SEL: u32 = 0xFF4C_9AFF;
const ENTRIES: [&[u8]; 4] = [b"bin", b"etc", b"home", b"capsules"];

struct Fm {
    sel: usize,
}

impl App for Fm {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 240, y: 170, width: 360, height: 260, z: 10 }
    }

    fn on_input(&mut self, ev: InputEvent) -> bool {
        if ev.kind != KIND_KEY_DOWN {
            return false;
        }
        match ev.code as u8 {
            b'j' => self.sel = (self.sel + 1) % ENTRIES.len(),
            b'k' => self.sel = (self.sel + ENTRIES.len() - 1) % ENTRIES.len(),
            13 => marker(b"[file_manager] open ", ENTRIES[self.sel]),
            _ => return false,
        }
        true
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        f.text(16, 18, b"file_manager  cwd=/", FG);
        let mut y = 56;
        for (i, e) in ENTRIES.iter().enumerate() {
            if i == self.sel {
                f.text(16, y, b">", SEL);
            }
            f.text(36, y, e, if i == self.sel { SEL } else { FG });
            y += 26;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(b"[file_manager] ", Fm { sel: 0 })
}
