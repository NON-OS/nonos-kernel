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

use crate::graphics::framebuffer::COLOR_GREEN;

pub(crate) fn signal_to_bars(rssi: i8) -> u32 {
    if rssi >= -50 {
        4
    } else if rssi >= -60 {
        3
    } else if rssi >= -70 {
        2
    } else if rssi >= -80 {
        1
    } else {
        0
    }
}

pub(crate) fn signal_color(rssi: i8) -> u32 {
    if rssi >= -50 {
        COLOR_GREEN
    } else if rssi >= -70 {
        0xFFFFB800
    } else {
        0xFFFF6B6B
    }
}

pub(crate) fn num_to_bytes(n: u32) -> [u8; 4] {
    let mut buf = [b' '; 4];
    let mut val = n;
    let mut i = 3usize;
    loop {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        if val == 0 || i == 0 {
            break;
        }
        i -= 1;
    }
    buf
}

pub(crate) fn rssi_to_str(rssi: i8) -> [u8; 8] {
    let mut buf = [b' '; 8];
    let abs_val = rssi.unsigned_abs();
    buf[0] = b'-';
    if abs_val >= 100 {
        buf[1] = b'0' + (abs_val / 100);
        buf[2] = b'0' + ((abs_val / 10) % 10);
        buf[3] = b'0' + (abs_val % 10);
        buf[4] = b'd';
        buf[5] = b'B';
        buf[6] = b'm';
    } else if abs_val >= 10 {
        buf[1] = b'0' + (abs_val / 10);
        buf[2] = b'0' + (abs_val % 10);
        buf[3] = b'd';
        buf[4] = b'B';
        buf[5] = b'm';
    } else {
        buf[1] = b'0' + abs_val;
        buf[2] = b'd';
        buf[3] = b'B';
        buf[4] = b'm';
    }
    buf
}

pub(crate) fn speed_to_str(rate: u32) -> [u8; 12] {
    let mut buf = [b' '; 12];
    let mbps = rate / 1000;
    let mut val = mbps;
    let mut i = 0usize;

    if val == 0 {
        buf[0] = b'0';
        i = 1;
    } else {
        let mut temp = [0u8; 6];
        let mut ti = 0;
        while val > 0 {
            temp[ti] = b'0' + (val % 10) as u8;
            val /= 10;
            ti += 1;
        }
        for j in (0..ti).rev() {
            buf[i] = temp[j];
            i += 1;
        }
    }
    buf[i] = b' ';
    buf[i + 1] = b'M';
    buf[i + 2] = b'b';
    buf[i + 3] = b'p';
    buf[i + 4] = b's';
    buf
}

pub(crate) fn format_mac(mac: &[u8; 6]) -> [u8; 22] {
    let mut buf = [b' '; 22];
    buf[0..5].copy_from_slice(b"MAC: ");
    let hex = b"0123456789ab";
    let mut pos = 5;
    for (i, &byte) in mac.iter().enumerate() {
        if i > 0 {
            buf[pos] = b':';
            pos += 1;
        }
        buf[pos] = hex[(byte >> 4) as usize];
        buf[pos + 1] = hex[(byte & 0x0f) as usize];
        pos += 2;
    }
    buf
}

pub(crate) fn format_ip(ip: &[u8; 4]) -> [u8; 16] {
    let mut buf = [b' '; 16];
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 {
            buf[pos] = b'.';
            pos += 1;
        }
        pos += write_u8(&mut buf[pos..], octet);
    }
    buf
}

pub(crate) fn format_ip_with_prefix(ip: &[u8; 4], prefix: u8) -> [u8; 20] {
    let mut buf = [b' '; 20];
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 {
            buf[pos] = b'.';
            pos += 1;
        }
        pos += write_u8(&mut buf[pos..], octet);
    }
    buf[pos] = b'/';
    pos += 1;
    write_u8(&mut buf[pos..], prefix);
    buf
}

pub(crate) fn write_u8(buf: &mut [u8], val: u8) -> usize {
    if val >= 100 {
        buf[0] = b'0' + (val / 100);
        buf[1] = b'0' + ((val / 10) % 10);
        buf[2] = b'0' + (val % 10);
        3
    } else if val >= 10 {
        buf[0] = b'0' + (val / 10);
        buf[1] = b'0' + (val % 10);
        2
    } else {
        buf[0] = b'0' + val;
        1
    }
}
