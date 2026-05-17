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

const BG: u32 = 0xFF12_1A14;
const FG: u32 = 0xFFE9_F2E9;

fn itoa(mut v: i64, out: &mut [u8]) -> usize {
    let neg = v < 0;
    if neg {
        v = -v;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    }
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut k = 0;
    if neg {
        out[0] = b'-';
        k = 1;
    }
    while n > 0 {
        n -= 1;
        out[k] = tmp[n];
        k += 1;
    }
    k
}

struct Calc {
    acc: i64,
    cur: i64,
    op: u8,
    fresh: bool,
}

impl Calc {
    fn apply(&mut self) {
        match self.op {
            b'+' => self.acc += self.cur,
            b'-' => self.acc -= self.cur,
            b'*' => self.acc *= self.cur,
            _ => self.acc = self.cur,
        }
        self.cur = 0;
    }
}

impl App for Calc {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 260, y: 180, width: 320, height: 200, z: 10 }
    }

    fn on_input(&mut self, ev: InputEvent) -> bool {
        if ev.kind != KIND_KEY_DOWN {
            return false;
        }
        let c = ev.code as u8;
        match c {
            b'0'..=b'9' => {
                self.cur = self.cur.saturating_mul(10) + (c - b'0') as i64;
                self.fresh = false;
            }
            b'+' | b'-' | b'*' => {
                self.apply();
                self.op = c;
            }
            b'=' | 13 => {
                self.apply();
                let mut b = [0u8; 24];
                let n = itoa(self.acc, &mut b);
                marker(b"[calculator] = ", &b[..n]);
                self.op = 0;
                self.fresh = true;
            }
            b'c' | b'C' => {
                self.acc = 0;
                self.cur = 0;
                self.op = 0;
                self.fresh = true;
            }
            _ => return false,
        }
        true
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        f.text(20, 24, b"calculator", FG);
        let mut b = [0u8; 24];
        let v = if self.fresh { self.acc } else { self.cur };
        let n = itoa(v, &mut b);
        f.text(20, 80, &b[..n], FG);
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(b"[calculator] ", Calc { acc: 0, cur: 0, op: 0, fresh: true })
}
