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

//! Range policy plus per-page presence/permission walk. Range rules
//! come from `policy::check_range`; permission decisions come from
//! `walk::translate_read` / `walk::translate_write`. No walker logic
//! and no permission constants live here.

use super::error::UsercopyError;
use super::policy::{check_range, PAGE_SIZE};
use super::walk::{translate_read, translate_write};

pub fn validate_user_read(addr: u64, len: usize) -> Result<(), UsercopyError> {
    validate(addr, len, false)
}

pub fn validate_user_write(addr: u64, len: usize) -> Result<(), UsercopyError> {
    validate(addr, len, true)
}

fn validate(addr: u64, len: usize, need_write: bool) -> Result<(), UsercopyError> {
    let Some(range) = check_range(addr, len)? else {
        return Ok(());
    };
    let mut page = range.start_page;
    while page <= range.end_page {
        if need_write {
            translate_write(page)?;
        } else {
            translate_read(page)?;
        }
        page = page.saturating_add(PAGE_SIZE);
        if page == 0 {
            break;
        }
    }
    Ok(())
}
