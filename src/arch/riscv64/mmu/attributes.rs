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

#[derive(Debug, Clone, Copy)]
pub struct PteFlags(u64);

impl PteFlags {
    pub const V: u64 = 1 << 0;
    pub const R: u64 = 1 << 1;
    pub const W: u64 = 1 << 2;
    pub const X: u64 = 1 << 3;
    pub const U: u64 = 1 << 4;
    pub const G: u64 = 1 << 5;
    pub const A: u64 = 1 << 6;
    pub const D: u64 = 1 << 7;

    pub const fn new() -> Self {
        Self(0)
    }

    pub const fn valid(mut self) -> Self {
        self.0 |= Self::V;
        self
    }

    pub const fn readable(mut self) -> Self {
        self.0 |= Self::R;
        self
    }

    pub const fn writable(mut self) -> Self {
        self.0 |= Self::W;
        self
    }

    pub const fn executable(mut self) -> Self {
        self.0 |= Self::X;
        self
    }

    pub const fn user(mut self) -> Self {
        self.0 |= Self::U;
        self
    }

    pub const fn global(mut self) -> Self {
        self.0 |= Self::G;
        self
    }

    pub const fn accessed(mut self) -> Self {
        self.0 |= Self::A;
        self
    }

    pub const fn dirty(mut self) -> Self {
        self.0 |= Self::D;
        self
    }

    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0 & Self::V != 0
    }

    pub fn is_leaf(&self) -> bool {
        self.0 & (Self::R | Self::W | Self::X) != 0
    }

    pub fn is_readable(&self) -> bool {
        self.0 & Self::R != 0
    }

    pub fn is_writable(&self) -> bool {
        self.0 & Self::W != 0
    }

    pub fn is_executable(&self) -> bool {
        self.0 & Self::X != 0
    }

    pub fn is_user(&self) -> bool {
        self.0 & Self::U != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageAttributes {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub user: bool,
    pub global: bool,
}

impl PageAttributes {
    pub const fn kernel_code() -> Self {
        Self { read: true, write: false, execute: true, user: false, global: true }
    }

    pub const fn kernel_data() -> Self {
        Self { read: true, write: true, execute: false, user: false, global: true }
    }

    pub const fn kernel_rodata() -> Self {
        Self { read: true, write: false, execute: false, user: false, global: true }
    }

    pub const fn user_code() -> Self {
        Self { read: true, write: false, execute: true, user: true, global: false }
    }

    pub const fn user_data() -> Self {
        Self { read: true, write: true, execute: false, user: true, global: false }
    }

    pub const fn user_rodata() -> Self {
        Self { read: true, write: false, execute: false, user: true, global: false }
    }

    pub fn to_pte_flags(&self) -> PteFlags {
        let mut flags = PteFlags::new().valid().accessed();

        if self.read {
            flags = flags.readable();
        }
        if self.write {
            flags = flags.writable().dirty();
        }
        if self.execute {
            flags = flags.executable();
        }
        if self.user {
            flags = flags.user();
        }
        if self.global {
            flags = flags.global();
        }

        flags
    }
}

impl Default for PageAttributes {
    fn default() -> Self {
        Self::kernel_data()
    }
}
