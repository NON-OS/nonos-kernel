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

use core::ptr::addr_of_mut;

use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::shell::output::print_line;

pub const MAX_ALIASES: usize = 32;
pub const MAX_ALIAS_NAME: usize = 16;
pub const MAX_ALIAS_VALUE: usize = 128;

#[derive(Clone, Copy)]
pub struct Alias {
    pub(crate) name: [u8; MAX_ALIAS_NAME],
    pub(crate) name_len: usize,
    pub(crate) value: [u8; MAX_ALIAS_VALUE],
    pub(crate) value_len: usize,
}

impl Alias {
    pub(crate) const fn empty() -> Self {
        Self {
            name: [0u8; MAX_ALIAS_NAME],
            name_len: 0,
            value: [0u8; MAX_ALIAS_VALUE],
            value_len: 0,
        }
    }
}

pub struct AliasTable {
    pub(crate) aliases: [Alias; MAX_ALIASES],
    pub(crate) count: usize,
}

impl AliasTable {
    pub const fn new() -> Self {
        Self {
            aliases: [Alias::empty(); MAX_ALIASES],
            count: 0,
        }
    }

    pub fn init_defaults(&mut self) {
        self.set(b"ll", b"ls -la");
        self.set(b"la", b"ls -a");
        self.set(b"cls", b"clear");
        self.set(b"h", b"history");
        self.set(b"...", b"cd ../..");
        self.set(b"q", b"exit");
        self.set(b"v", b"vault");
        self.set(b"t", b"tor");
    }

    pub fn set(&mut self, name: &[u8], value: &[u8]) -> bool {
        for i in 0..self.count {
            if self.aliases[i].name_len == name.len()
                && &self.aliases[i].name[..name.len()] == name
            {
                let val_len = value.len().min(MAX_ALIAS_VALUE);
                self.aliases[i].value[..val_len].copy_from_slice(&value[..val_len]);
                self.aliases[i].value_len = val_len;
                return true;
            }
        }

        if self.count >= MAX_ALIASES {
            return false;
        }

        let name_len = name.len().min(MAX_ALIAS_NAME);
        let val_len = value.len().min(MAX_ALIAS_VALUE);

        self.aliases[self.count].name[..name_len].copy_from_slice(&name[..name_len]);
        self.aliases[self.count].name_len = name_len;
        self.aliases[self.count].value[..val_len].copy_from_slice(&value[..val_len]);
        self.aliases[self.count].value_len = val_len;
        self.count += 1;

        true
    }

    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.count {
            if self.aliases[i].name_len == name.len()
                && &self.aliases[i].name[..name.len()] == name
            {
                return Some(&self.aliases[i].value[..self.aliases[i].value_len]);
            }
        }
        None
    }

    pub fn unset(&mut self, name: &[u8]) -> bool {
        for i in 0..self.count {
            if self.aliases[i].name_len == name.len()
                && &self.aliases[i].name[..name.len()] == name
            {
                for j in i..(self.count - 1) {
                    self.aliases[j] = self.aliases[j + 1];
                }
                self.aliases[self.count - 1] = Alias::empty();
                self.count -= 1;
                return true;
            }
        }
        false
    }

    pub fn list(&self) {
        print_line(b"Defined Aliases:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);

        if self.count == 0 {
            print_line(b"(no aliases defined)", COLOR_TEXT_DIM);
            return;
        }

        for i in 0..self.count {
            let alias = &self.aliases[i];
            let mut line = [0u8; 160];

            line[..6].copy_from_slice(b"alias ");
            let mut pos = 6;

            let name_len = alias.name_len;
            line[pos..pos + name_len].copy_from_slice(&alias.name[..name_len]);
            pos += name_len;

            line[pos..pos + 2].copy_from_slice(b"='");
            pos += 2;

            let val_len = alias.value_len.min(80);
            line[pos..pos + val_len].copy_from_slice(&alias.value[..val_len]);
            pos += val_len;

            line[pos] = b'\'';
            pos += 1;

            print_line(&line[..pos], COLOR_GREEN);
        }

        print_line(b"", COLOR_TEXT);
        print_line(b"(Aliases stored in RAM only)", COLOR_YELLOW);
    }

    pub fn expand(&self, cmd: &[u8]) -> Option<([u8; 256], usize)> {
        let first_word_end = cmd.iter().position(|&c| c == b' ').unwrap_or(cmd.len());
        let first_word = &cmd[..first_word_end];

        if let Some(expansion) = self.get(first_word) {
            let mut result = [0u8; 256];
            let exp_len = expansion.len();
            result[..exp_len].copy_from_slice(expansion);

            if first_word_end < cmd.len() {
                let rest = &cmd[first_word_end..];
                let rest_len = rest.len().min(256 - exp_len);
                result[exp_len..exp_len + rest_len].copy_from_slice(&rest[..rest_len]);
                return Some((result, exp_len + rest_len));
            }

            return Some((result, exp_len));
        }

        None
    }

    pub fn secure_erase(&mut self) {
        for i in 0..MAX_ALIASES {
            for j in 0..MAX_ALIAS_NAME {
                // SAFETY: write_volatile prevents optimization of zeroing.
                unsafe {
                    core::ptr::write_volatile(&mut self.aliases[i].name[j], 0);
                }
            }
            for j in 0..MAX_ALIAS_VALUE {
                unsafe {
                    core::ptr::write_volatile(&mut self.aliases[i].value[j], 0);
                }
            }
            self.aliases[i].name_len = 0;
            self.aliases[i].value_len = 0;
        }
        self.count = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

static mut ALIASES: AliasTable = AliasTable::new();

pub fn get_aliases() -> &'static mut AliasTable {
    // SAFETY: Alias table is only accessed from the main thread.
    unsafe { &mut *addr_of_mut!(ALIASES) }
}

pub fn init_aliases() {
    get_aliases().init_defaults();
}

pub fn expand_alias(cmd: &[u8]) -> Option<([u8; 256], usize)> {
    get_aliases().expand(cmd)
}
