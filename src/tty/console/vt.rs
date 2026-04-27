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

extern crate alloc;

use super::screen::ScreenBuffer;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const MAX_VTS: usize = 8;
static ACTIVE_VT: AtomicUsize = AtomicUsize::new(0);
static VTS: Mutex<[Option<Arc<VirtualTerminal>>; MAX_VTS]> = Mutex::new([const { None }; MAX_VTS]);

pub struct VirtualTerminal {
    pub num: usize,
    pub screen: Mutex<ScreenBuffer>,
    pub cursor_x: AtomicUsize,
    pub cursor_y: AtomicUsize,
}

impl VirtualTerminal {
    pub fn new(num: usize, rows: usize, cols: usize) -> Self {
        Self {
            num,
            screen: Mutex::new(ScreenBuffer::new(rows, cols)),
            cursor_x: AtomicUsize::new(0),
            cursor_y: AtomicUsize::new(0),
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, i32> {
        let mut screen = self.screen.lock();
        for &c in buf {
            match c {
                b'\n' => {
                    self.cursor_x.store(0, Ordering::SeqCst);
                    let y = self.cursor_y.fetch_add(1, Ordering::SeqCst);
                    if y >= screen.rows - 1 {
                        screen.scroll_up();
                        self.cursor_y.store(screen.rows - 1, Ordering::SeqCst);
                    }
                }
                b'\r' => {
                    self.cursor_x.store(0, Ordering::SeqCst);
                }
                b'\t' => {
                    let x = self.cursor_x.load(Ordering::SeqCst);
                    self.cursor_x.store((x + 8) & !7, Ordering::SeqCst);
                }
                _ => {
                    let x = self.cursor_x.load(Ordering::SeqCst);
                    let y = self.cursor_y.load(Ordering::SeqCst);
                    screen.put_char(x, y, c);
                    if x + 1 >= screen.cols {
                        self.cursor_x.store(0, Ordering::SeqCst);
                        let ny = self.cursor_y.fetch_add(1, Ordering::SeqCst);
                        if ny >= screen.rows - 1 {
                            screen.scroll_up();
                            self.cursor_y.store(screen.rows - 1, Ordering::SeqCst);
                        }
                    } else {
                        self.cursor_x.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        if self.num == ACTIVE_VT.load(Ordering::SeqCst) {
            screen.flush_to_display();
        }
        Ok(buf.len())
    }
}

pub fn init_vts() {
    let mut vts = VTS.lock();
    for i in 0..MAX_VTS {
        vts[i] = Some(Arc::new(VirtualTerminal::new(i, 25, 80)));
    }
}

pub fn switch_vt(num: usize) -> Result<(), i32> {
    if num >= MAX_VTS {
        return Err(-22);
    }
    ACTIVE_VT.store(num, Ordering::SeqCst);
    if let Some(vt) = VTS.lock()[num].as_ref() {
        vt.screen.lock().flush_to_display();
    }
    Ok(())
}

pub fn get_active_vt() -> Option<Arc<VirtualTerminal>> {
    let idx = ACTIVE_VT.load(Ordering::SeqCst);
    if idx >= MAX_VTS {
        return None;
    }
    VTS.lock()[idx].as_ref().cloned()
}

pub fn console_ioctl(cmd: u32, arg: u64) -> Result<i64, i32> {
    match cmd {
        0x5606 => switch_vt(arg as usize).map(|_| 0),
        0x5600 => Ok(ACTIVE_VT.load(Ordering::SeqCst) as i64),
        _ => Err(-25),
    }
}
