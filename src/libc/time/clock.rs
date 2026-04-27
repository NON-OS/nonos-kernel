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

use core::ptr;

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

#[no_mangle]
pub unsafe extern "C" fn time(tloc: *mut i64) -> i64 {
    let mut ts = Timespec::default();
    if clock_gettime(CLOCK_REALTIME, &mut ts) < 0 {
        return -1;
    }
    if !tloc.is_null() {
        ptr::write(tloc, ts.tv_sec);
    }
    ts.tv_sec
}

#[no_mangle]
pub unsafe extern "C" fn clock_gettime(clockid: i32, tp: *mut Timespec) -> i32 {
    let ret = crate::syscall::sys_clock_gettime(clockid, tp as u64);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn clock_settime(clockid: i32, tp: *const Timespec) -> i32 {
    let ret = crate::syscall::sys_clock_settime(clockid, tp as u64);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn clock_getres(clockid: i32, res: *mut Timespec) -> i32 {
    let ret = crate::syscall::sys_clock_getres(clockid, res as u64);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn gettimeofday(tv: *mut Timeval, _tz: *mut u8) -> i32 {
    if tv.is_null() {
        return 0;
    }
    let mut ts = Timespec::default();
    if clock_gettime(CLOCK_REALTIME, &mut ts) < 0 {
        return -1;
    }
    (*tv).tv_sec = ts.tv_sec;
    (*tv).tv_usec = ts.tv_nsec / 1000;
    0
}

#[no_mangle]
pub unsafe extern "C" fn settimeofday(tv: *const Timeval, _tz: *const u8) -> i32 {
    if tv.is_null() {
        return -1;
    }
    let ts = Timespec { tv_sec: (*tv).tv_sec, tv_nsec: (*tv).tv_usec * 1000 };
    clock_settime(CLOCK_REALTIME, &ts)
}

#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> i32 {
    let ret = crate::syscall::sys_nanosleep(req as u64, rem as u64);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn clock_nanosleep(
    clockid: i32,
    flags: i32,
    req: *const Timespec,
    rem: *mut Timespec,
) -> i32 {
    let ret = crate::syscall::sys_clock_nanosleep(clockid, flags, req as u64, rem as u64);
    if ret < 0 {
        return (-ret) as i32;
    }
    0
}

#[thread_local]
static mut TM_BUFFER: Tm = Tm {
    tm_sec: 0,
    tm_min: 0,
    tm_hour: 0,
    tm_mday: 1,
    tm_mon: 0,
    tm_year: 70,
    tm_wday: 4,
    tm_yday: 0,
    tm_isdst: 0,
};
const DAYS_PER_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
fn is_leap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

#[no_mangle]
pub unsafe extern "C" fn gmtime(timep: *const i64) -> *mut Tm {
    if timep.is_null() {
        return ptr::null_mut();
    }
    let t = *timep;
    let mut days = (t / 86400) as i32;
    let rem = (t % 86400) as i32;
    TM_BUFFER.tm_hour = rem / 3600;
    TM_BUFFER.tm_min = (rem % 3600) / 60;
    TM_BUFFER.tm_sec = rem % 60;
    TM_BUFFER.tm_wday = ((days + 4) % 7 + 7) % 7;
    let mut year = 1970i32;
    while days >= if is_leap(year) { 366 } else { 365 } {
        days -= if is_leap(year) { 366 } else { 365 };
        year += 1;
    }
    while days < 0 {
        year -= 1;
        days += if is_leap(year) { 366 } else { 365 };
    }
    TM_BUFFER.tm_year = year - 1900;
    TM_BUFFER.tm_yday = days;
    let leap = is_leap(year);
    let mut mon = 0;
    while mon < 12 {
        let d = if mon == 1 && leap { 29 } else { DAYS_PER_MONTH[mon] };
        if days < d {
            break;
        }
        days -= d;
        mon += 1;
    }
    TM_BUFFER.tm_mon = mon as i32;
    TM_BUFFER.tm_mday = days + 1;
    TM_BUFFER.tm_isdst = 0;
    &raw mut TM_BUFFER
}

#[no_mangle]
pub unsafe extern "C" fn localtime(timep: *const i64) -> *mut Tm {
    gmtime(timep)
}

#[no_mangle]
pub unsafe extern "C" fn mktime(tm: *mut Tm) -> i64 {
    if tm.is_null() {
        return -1;
    }
    let t = &*tm;
    let y = t.tm_year + 1900;
    let mut days = (y - 1970) * 365 + (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400;
    for m in 0..t.tm_mon {
        days += if m == 1 && is_leap(y) { 29 } else { DAYS_PER_MONTH[m as usize] };
    }
    days += t.tm_mday - 1;
    (days as i64) * 86400 + (t.tm_hour as i64) * 3600 + (t.tm_min as i64) * 60 + t.tm_sec as i64
}

#[no_mangle]
pub unsafe extern "C" fn strftime(s: *mut u8, max: usize, fmt: *const u8, tm: *const Tm) -> usize {
    if s.is_null() || max == 0 || fmt.is_null() || tm.is_null() {
        return 0;
    }
    let t = &*tm;
    let mut pos = 0;
    let mut i = 0;
    while ptr::read(fmt.add(i)) != 0 && pos < max - 1 {
        let c = ptr::read(fmt.add(i));
        if c == b'%' {
            i += 1;
            match ptr::read(fmt.add(i)) {
                b'Y' => {
                    let n = write_num(
                        &mut *ptr::slice_from_raw_parts_mut(s.add(pos), max - pos),
                        t.tm_year + 1900,
                        4,
                    );
                    pos += n;
                }
                b'm' => {
                    let n = write_num(
                        &mut *ptr::slice_from_raw_parts_mut(s.add(pos), max - pos),
                        t.tm_mon + 1,
                        2,
                    );
                    pos += n;
                }
                b'd' => {
                    let n = write_num(
                        &mut *ptr::slice_from_raw_parts_mut(s.add(pos), max - pos),
                        t.tm_mday,
                        2,
                    );
                    pos += n;
                }
                b'H' => {
                    let n = write_num(
                        &mut *ptr::slice_from_raw_parts_mut(s.add(pos), max - pos),
                        t.tm_hour,
                        2,
                    );
                    pos += n;
                }
                b'M' => {
                    let n = write_num(
                        &mut *ptr::slice_from_raw_parts_mut(s.add(pos), max - pos),
                        t.tm_min,
                        2,
                    );
                    pos += n;
                }
                b'S' => {
                    let n = write_num(
                        &mut *ptr::slice_from_raw_parts_mut(s.add(pos), max - pos),
                        t.tm_sec,
                        2,
                    );
                    pos += n;
                }
                _ => {}
            }
        } else {
            ptr::write(s.add(pos), c);
            pos += 1;
        }
        i += 1;
    }
    ptr::write(s.add(pos), 0);
    pos
}

fn write_num(buf: &mut [u8], mut v: i32, width: usize) -> usize {
    let mut tmp = [b'0'; 10];
    let mut i = 0;
    if v == 0 {
        tmp[0] = b'0';
        i = 1;
    }
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i < width {
        tmp[i] = b'0';
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}
