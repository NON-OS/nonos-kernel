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


use core::sync::atomic::{AtomicU8, Ordering};

static CURRENT_TAB: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tab {
    Browser = 0,
    Wallet = 1,
    Staking = 2,
    LP = 3,
    Privacy = 4,
    Node = 5,
}

impl Tab {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "Browser",
            Self::Wallet => "Wallet",
            Self::Staking => "Staking",
            Self::LP => "LP",
            Self::Privacy => "Privacy",
            Self::Node => "Node",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Self::Browser => "globe",
            Self::Wallet => "wallet",
            Self::Staking => "stake",
            Self::LP => "pool",
            Self::Privacy => "shield",
            Self::Node => "server",
        }
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Browser),
            1 => Some(Self::Wallet),
            2 => Some(Self::Staking),
            3 => Some(Self::LP),
            4 => Some(Self::Privacy),
            5 => Some(Self::Node),
            _ => None,
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Browser => Self::Wallet,
            Self::Wallet => Self::Staking,
            Self::Staking => Self::LP,
            Self::LP => Self::Privacy,
            Self::Privacy => Self::Node,
            Self::Node => Self::Browser,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Browser => Self::Node,
            Self::Wallet => Self::Browser,
            Self::Staking => Self::Wallet,
            Self::LP => Self::Staking,
            Self::Privacy => Self::LP,
            Self::Node => Self::Privacy,
        }
    }

    pub const fn all() -> [Tab; 6] {
        [
            Self::Browser,
            Self::Wallet,
            Self::Staking,
            Self::LP,
            Self::Privacy,
            Self::Node,
        ]
    }
}

impl Default for Tab {
    fn default() -> Self {
        Self::Browser
    }
}

pub fn current_tab() -> Tab {
    Tab::from_u8(CURRENT_TAB.load(Ordering::Relaxed)).unwrap_or(Tab::Browser)
}

pub fn set_tab(tab: Tab) {
    CURRENT_TAB.store(tab as u8, Ordering::Relaxed);
}

pub fn next_tab() {
    let current = current_tab();
    set_tab(current.next());
}

pub fn prev_tab() {
    let current = current_tab();
    set_tab(current.prev());
}
