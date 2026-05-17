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

const BG: u32 = 0xFF0A_0F0A;
const FG: u32 = 0xFF8C_F08C;
const ROWS: usize = 6;
const COLS: usize = 64;

struct Term {
    line: [u8; COLS],
    len: usize,
    hist: [[u8; COLS]; ROWS],
    hl: [usize; ROWS],
    rows: usize,
}

impl Term {
    fn push(&mut self) {
        if self.rows < ROWS {
            self.hist[self.rows][..self.len].copy_from_slice(&self.line[..self.len]);
            self.hl[self.rows] = self.len;
            self.rows += 1;
        } else {
            for i in 1..ROWS {
                self.hist[i - 1] = self.hist[i];
                self.hl[i - 1] = self.hl[i];
            }
            self.hist[ROWS - 1][..self.len].copy_from_slice(&self.line[..self.len]);
            self.hl[ROWS - 1] = self.len;
        }
        marker(b"[terminal] ", &self.line[..self.len]);
        self.len = 0;
    }
}

impl App for Term {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 200, y: 140, width: 520, height: 300, z: 10 }
    }

    fn on_input(&mut self, ev: InputEvent) -> bool {
        if ev.kind != KIND_KEY_DOWN {
            return false;
        }
        let c = ev.code as u8;
        if c == 13 || c == 10 {
            self.push();
        } else if (c == 8 || c == 127) && self.len > 0 {
            self.len -= 1;
        } else if c >= 0x20 && self.len < COLS {
            self.line[self.len] = c;
            self.len += 1;
        } else {
            return false;
        }
        true
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        let mut y = 20;
        for i in 0..self.rows {
            f.text(12, y, &self.hist[i][..self.hl[i]], FG);
            y += 22;
        }
        let mut p = [0u8; COLS + 2];
        p[0] = b'$';
        p[1] = b' ';
        let n = self.len.min(COLS);
        p[2..2 + n].copy_from_slice(&self.line[..n]);
        f.text(12, y, &p[..2 + n], FG);
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(
        b"[terminal] ",
        Term { line: [0; COLS], len: 0, hist: [[0; COLS]; ROWS], hl: [0; ROWS], rows: 0 },
    )
}
