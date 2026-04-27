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

pub const NCCS: usize = 19;
pub const IGNBRK: u32 = 0x001;
pub const BRKINT: u32 = 0x002;
pub const IGNPAR: u32 = 0x004;
pub const PARMRK: u32 = 0x008;
pub const INPCK: u32 = 0x010;
pub const ISTRIP: u32 = 0x020;
pub const INLCR: u32 = 0x040;
pub const IGNCR: u32 = 0x080;
pub const ICRNL: u32 = 0x100;
pub const IXON: u32 = 0x400;
pub const IXANY: u32 = 0x800;
pub const IXOFF: u32 = 0x1000;
pub const OPOST: u32 = 0x001;
pub const ONLCR: u32 = 0x004;
pub const OCRNL: u32 = 0x008;
pub const ONOCR: u32 = 0x010;
pub const ONLRET: u32 = 0x020;
pub const OFILL: u32 = 0x040;
pub const ISIG: u32 = 0x001;
pub const ICANON: u32 = 0x002;
pub const ECHO: u32 = 0x008;
pub const ECHOE: u32 = 0x010;
pub const ECHOK: u32 = 0x020;
pub const ECHONL: u32 = 0x040;
pub const NOFLSH: u32 = 0x080;
pub const TOSTOP: u32 = 0x100;
pub const IEXTEN: u32 = 0x8000;
pub const CSIZE: u32 = 0x030;
pub const CS5: u32 = 0x000;
pub const CS6: u32 = 0x010;
pub const CS7: u32 = 0x020;
pub const CS8: u32 = 0x030;
pub const CSTOPB: u32 = 0x040;
pub const CREAD: u32 = 0x080;
pub const PARENB: u32 = 0x100;
pub const PARODD: u32 = 0x200;
pub const HUPCL: u32 = 0x400;
pub const CLOCAL: u32 = 0x800;
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Default for Termios {
    fn default() -> Self {
        let mut t = Self {
            c_iflag: ICRNL | IXON,
            c_oflag: OPOST | ONLCR,
            c_cflag: CS8 | CREAD | CLOCAL,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN,
            c_line: 0,
            c_cc: [0; NCCS],
            c_ispeed: 38400,
            c_ospeed: 38400,
        };
        t.c_cc[VINTR] = 3;
        t.c_cc[VQUIT] = 28;
        t.c_cc[VERASE] = 127;
        t.c_cc[VKILL] = 21;
        t.c_cc[VEOF] = 4;
        t.c_cc[VTIME] = 0;
        t.c_cc[VMIN] = 1;
        t.c_cc[VSTART] = 17;
        t.c_cc[VSTOP] = 19;
        t.c_cc[VSUSP] = 26;
        t.c_cc[VEOL] = 0;
        t
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

impl Winsize {
    pub fn new(rows: u16, cols: u16) -> Self {
        Self { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 }
    }
}
