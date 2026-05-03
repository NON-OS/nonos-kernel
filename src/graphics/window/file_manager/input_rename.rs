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

use super::state::{
    clear_input, push_input_char, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_RENAMING, FM_SELECTED_ITEM,
};
use core::sync::atomic::Ordering;

pub fn start_rename() {
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return;
    }

    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    clear_input();
    for &ch in entry.name[..entry.name_len as usize].iter() {
        push_input_char(ch);
    }

    FM_RENAMING.store(true, Ordering::Relaxed);
}
