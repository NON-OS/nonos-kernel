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

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use spin::Mutex;

pub use super::state_browser::*;
pub use super::state_links::*;
pub use super::state_page::*;
pub use super::state_privacy::*;
pub use super::state_wallet::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EcosystemTab {
    Browser = 0,
    Wallet = 1,
}

impl EcosystemTab {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Browser,
            1 => Self::Wallet,
            _ => Self::Browser,
        }
    }
    pub fn label(&self) -> &'static [u8] {
        match self {
            Self::Browser => b"Browser",
            Self::Wallet => b"Wallet",
        }
    }
    pub fn count() -> usize {
        2
    }
}

pub static ACTIVE_TAB: AtomicU8 = AtomicU8::new(0);
pub fn get_active_tab() -> EcosystemTab {
    EcosystemTab::from_u8(ACTIVE_TAB.load(Ordering::Relaxed))
}
pub fn set_active_tab(tab: EcosystemTab) {
    ACTIVE_TAB.store(tab as u8, Ordering::Relaxed);
}

pub static INPUT_FOCUSED: AtomicBool = AtomicBool::new(false);
pub fn is_input_focused() -> bool {
    INPUT_FOCUSED.load(Ordering::Relaxed)
}
pub fn set_input_focused(focused: bool) {
    INPUT_FOCUSED.store(focused, Ordering::Relaxed);
}

pub const MAX_INPUT_LEN: usize = 256;
pub static INPUT_BUFFER: Mutex<[u8; MAX_INPUT_LEN]> = Mutex::new([0u8; MAX_INPUT_LEN]);
pub static INPUT_LEN: AtomicUsize = AtomicUsize::new(0);
pub static INPUT_CURSOR: AtomicUsize = AtomicUsize::new(0);
