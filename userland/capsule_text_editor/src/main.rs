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

const BG: u32 = 0xFF1A_1620;
const FG: u32 = 0xFFF2_E9F2;
const CAP: usize = 256;
const WRAP: usize = 48;

struct Editor {
    buf: [u8; CAP],
    len: usize,
}

impl App for Editor {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 210, y: 150, width: 500, height: 320, z: 10 }
    }

    fn on_input(&mut self, ev: InputEvent) -> bool {
        if ev.kind != KIND_KEY_DOWN {
            return false;
        }
        let c = ev.code as u8;
        if (c == 8 || c == 127) && self.len > 0 {
            self.len -= 1;
        } else if (c == b'\n' || c == 13) && self.len < CAP {
            self.buf[self.len] = b'\n';
            self.len += 1;
        } else if c >= 0x20 && self.len < CAP {
            self.buf[self.len] = c;
            self.len += 1;
        } else {
            return false;
        }
        marker(b"[text_editor] ", b"edit");
        true
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        f.text(16, 18, b"text_editor", FG);
        let mut y = 48;
        let mut x = 16;
        let mut col = 0;
        for i in 0..self.len {
            let ch = self.buf[i];
            if ch == b'\n' || col == WRAP {
                y += 20;
                x = 16;
                col = 0;
                if ch == b'\n' {
                    continue;
                }
            }
            f.text(x, y, &[ch], FG);
            x += 9;
            col += 1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(b"[text_editor] ", Editor { buf: [0; CAP], len: 0 })
}
