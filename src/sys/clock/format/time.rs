// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::sys::clock::time::get_time;

pub fn format_time(buf: &mut [u8; 5]) {
    let time = get_time();
    buf[0] = b'0' + (time.hour / 10);
    buf[1] = b'0' + (time.hour % 10);
    buf[2] = b':';
    buf[3] = b'0' + (time.minute / 10);
    buf[4] = b'0' + (time.minute % 10);
}

pub fn format_time_full(buf: &mut [u8; 8]) {
    let time = get_time();
    buf[0] = b'0' + (time.hour / 10);
    buf[1] = b'0' + (time.hour % 10);
    buf[2] = b':';
    buf[3] = b'0' + (time.minute / 10);
    buf[4] = b'0' + (time.minute % 10);
    buf[5] = b':';
    buf[6] = b'0' + (time.second / 10);
    buf[7] = b'0' + (time.second % 10);
}
