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

use super::pair::get_pair;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn unlock(pty_num: u32) -> Result<(), i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    pair.unlocked.store(true, Ordering::SeqCst);
    Ok(())
}

pub fn get_pty_name(pty_num: u32) -> Result<String, i32> {
    if !super::pair::pair_exists(pty_num) {
        return Err(-9);
    }
    Ok(format!("/dev/pts/{}", pty_num))
}

pub fn grantpt(pty_num: u32) -> Result<(), i32> {
    let _pair = get_pair(pty_num).ok_or(-9)?;
    Ok(())
}

pub fn ptsname(pty_num: u32) -> Result<String, i32> {
    get_pty_name(pty_num)
}

pub fn is_unlocked(pty_num: u32) -> bool {
    get_pair(pty_num).map(|p| p.unlocked.load(Ordering::SeqCst)).unwrap_or(false)
}

pub fn lock(pty_num: u32) -> Result<(), i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    pair.unlocked.store(false, Ordering::SeqCst);
    Ok(())
}
