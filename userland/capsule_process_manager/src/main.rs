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

const BG: u32 = 0xFF18_1212;
const FG: u32 = 0xFFEC_D7D7;
const WARN: u32 = 0xFFF2_A65A;

struct Pm {
    refreshes: u32,
}

fn u32a(mut v: u32, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 10];
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
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

impl App for Pm {
    fn window(&self) -> WindowCfg {
        WindowCfg { x: 230, y: 160, width: 440, height: 240, z: 10 }
    }

    fn on_input(&mut self, ev: InputEvent) -> bool {
        if ev.kind != KIND_KEY_DOWN {
            return false;
        }
        self.refreshes = self.refreshes.wrapping_add(1);
        marker(b"[process_manager] ", b"refresh");
        true
    }

    fn render(&mut self, f: &mut Frame) {
        f.fill(BG);
        f.text(16, 18, b"process_manager", FG);
        f.text(16, 56, b"kernel observability op: E_NOSYS", WARN);
        f.text(16, 80, b"(pending debug-gated syscall)", WARN);
        let mut b = [0u8; 10];
        let n = u32a(self.refreshes, &mut b);
        f.text(16, 120, b"refreshes: ", FG);
        f.text(160, 120, &b[..n], FG);
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    run(b"[process_manager] ", Pm { refreshes: 0 })
}
