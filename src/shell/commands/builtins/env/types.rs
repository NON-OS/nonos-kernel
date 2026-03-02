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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};

pub const MAX_ENV_VARS: usize = 32;
pub const MAX_VAR_NAME: usize = 32;
pub const MAX_VAR_VALUE: usize = 128;

#[derive(Clone, Copy)]
pub struct EnvVar {
    pub(crate) name: [u8; MAX_VAR_NAME],
    pub(crate) name_len: usize,
    pub(crate) value: [u8; MAX_VAR_VALUE],
    pub(crate) value_len: usize,
    pub(crate) exported: bool,
}

impl EnvVar {
    pub(crate) const fn empty() -> Self {
        Self {
            name: [0u8; MAX_VAR_NAME],
            name_len: 0,
            value: [0u8; MAX_VAR_VALUE],
            value_len: 0,
            exported: false,
        }
    }
}

pub struct Environment {
    pub(crate) vars: [EnvVar; MAX_ENV_VARS],
    pub(crate) count: usize,
}

impl Environment {
    pub const fn new() -> Self {
        Self {
            vars: [EnvVar::empty(); MAX_ENV_VARS],
            count: 0,
        }
    }

    pub fn init_defaults(&mut self) {
        self.set(b"USER", b"anonymous", true);
        self.set(b"HOME", b"/home/anonymous", true);
        self.set(b"SHELL", b"/bin/nsh", true);
        self.set(b"PATH", b"/bin:/capsules/bin", true);
        self.set(b"TERM", b"nonos-term", true);
        self.set(b"ANON_MODE", b"true", true);
        self.set(b"ZEROSTATE", b"active", true);
        self.set(b"TOR_ENABLED", b"true", true);
        self.set(b"PWD", b"/home/anonymous", true);
        self.set(b"LANG", b"C.UTF-8", true);
    }

    pub fn set(&mut self, name: &[u8], value: &[u8], export: bool) -> bool {
        for i in 0..self.count {
            if self.vars[i].name_len == name.len() && &self.vars[i].name[..name.len()] == name {
                let val_len = value.len().min(MAX_VAR_VALUE);
                self.vars[i].value[..val_len].copy_from_slice(&value[..val_len]);
                self.vars[i].value_len = val_len;
                if export {
                    self.vars[i].exported = true;
                }
                return true;
            }
        }

        if self.count >= MAX_ENV_VARS {
            return false;
        }

        let name_len = name.len().min(MAX_VAR_NAME);
        let val_len = value.len().min(MAX_VAR_VALUE);

        self.vars[self.count].name[..name_len].copy_from_slice(&name[..name_len]);
        self.vars[self.count].name_len = name_len;
        self.vars[self.count].value[..val_len].copy_from_slice(&value[..val_len]);
        self.vars[self.count].value_len = val_len;
        self.vars[self.count].exported = export;
        self.count += 1;

        true
    }

    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.count {
            if self.vars[i].name_len == name.len() && &self.vars[i].name[..name.len()] == name {
                return Some(&self.vars[i].value[..self.vars[i].value_len]);
            }
        }
        None
    }

    pub fn unset(&mut self, name: &[u8]) -> bool {
        for i in 0..self.count {
            if self.vars[i].name_len == name.len() && &self.vars[i].name[..name.len()] == name {
                for j in i..(self.count - 1) {
                    self.vars[j] = self.vars[j + 1];
                }
                self.vars[self.count - 1] = EnvVar::empty();
                self.count -= 1;
                return true;
            }
        }
        false
    }

    pub fn list_all(&self) {
        print_line(b"Environment Variables:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);

        for i in 0..self.count {
            let var = &self.vars[i];
            let mut line = [0u8; 180];
            let mut pos = 0;

            let name_len = var.name_len;
            line[pos..pos + name_len].copy_from_slice(&var.name[..name_len]);
            pos += name_len;

            line[pos] = b'=';
            pos += 1;

            let val_len = var.value_len.min(80);
            line[pos..pos + val_len].copy_from_slice(&var.value[..val_len]);
            pos += val_len;

            let color = if var.exported { COLOR_GREEN } else { COLOR_TEXT };
            print_line(&line[..pos], color);
        }
    }

    pub fn list_exported(&self) {
        print_line(b"Exported Variables:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);

        for i in 0..self.count {
            let var = &self.vars[i];
            if !var.exported {
                continue;
            }

            let mut line = [0u8; 180];
            line[..7].copy_from_slice(b"export ");
            let mut pos = 7;

            let name_len = var.name_len;
            line[pos..pos + name_len].copy_from_slice(&var.name[..name_len]);
            pos += name_len;

            line[pos..pos + 2].copy_from_slice(b"=\"");
            pos += 2;

            let val_len = var.value_len.min(70);
            line[pos..pos + val_len].copy_from_slice(&var.value[..val_len]);
            pos += val_len;

            line[pos] = b'"';
            pos += 1;

            print_line(&line[..pos], COLOR_GREEN);
        }
    }

    pub fn secure_erase(&mut self) {
        for i in 0..MAX_ENV_VARS {
            for j in 0..MAX_VAR_NAME {
                // SAFETY: write_volatile prevents optimization of zeroing.
                unsafe {
                    core::ptr::write_volatile(&mut self.vars[i].name[j], 0);
                }
            }
            for j in 0..MAX_VAR_VALUE {
                unsafe {
                    core::ptr::write_volatile(&mut self.vars[i].value[j], 0);
                }
            }
            self.vars[i].name_len = 0;
            self.vars[i].value_len = 0;
            self.vars[i].exported = false;
        }
        self.count = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

static mut ENV: Environment = Environment::new();

pub fn get_env() -> &'static mut Environment {
    // SAFETY: Environment is only accessed from the main thread.
    unsafe { &mut *addr_of_mut!(ENV) }
}

pub fn init_env() {
    get_env().init_defaults();
}
