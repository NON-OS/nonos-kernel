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
pub use super::state_wallet::*;
pub use super::state_page::*;
pub use super::state_links::*;
pub use super::state_privacy::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EcosystemTab {
    Browser = 0, Wallet = 1, Staking = 2, Liquidity = 3, Node = 4, Privacy = 5,
}

impl EcosystemTab {
    pub fn from_u8(v: u8) -> Self {
        match v { 0 => Self::Browser, 1 => Self::Wallet, 2 => Self::Staking, 3 => Self::Liquidity, 4 => Self::Node, 5 => Self::Privacy, _ => Self::Browser }
    }
    pub fn label(&self) -> &'static [u8] {
        match self { Self::Browser => b"Browser", Self::Wallet => b"Wallet", Self::Staking => b"Staking", Self::Liquidity => b"LP", Self::Node => b"Node", Self::Privacy => b"Privacy" }
    }
    pub fn count() -> usize { 6 }
}

pub static ACTIVE_TAB: AtomicU8 = AtomicU8::new(0);
pub fn get_active_tab() -> EcosystemTab { EcosystemTab::from_u8(ACTIVE_TAB.load(Ordering::Relaxed)) }
pub fn set_active_tab(tab: EcosystemTab) { ACTIVE_TAB.store(tab as u8, Ordering::Relaxed); }

pub static INPUT_FOCUSED: AtomicBool = AtomicBool::new(false);
pub fn is_input_focused() -> bool { INPUT_FOCUSED.load(Ordering::Relaxed) }
pub fn set_input_focused(focused: bool) { INPUT_FOCUSED.store(focused, Ordering::Relaxed); }

pub const MAX_INPUT_LEN: usize = 256;
pub static INPUT_BUFFER: Mutex<[u8; MAX_INPUT_LEN]> = Mutex::new([0u8; MAX_INPUT_LEN]);
pub static INPUT_LEN: AtomicUsize = AtomicUsize::new(0);
pub static INPUT_CURSOR: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EcosystemView { Main = 0, Swap = 1, NodeSettings = 2 }
pub static CURRENT_VIEW: AtomicU8 = AtomicU8::new(0);
pub fn set_current_view(view: EcosystemView) { CURRENT_VIEW.store(view as u8, Ordering::Relaxed); }
pub fn get_current_view() -> EcosystemView {
    match CURRENT_VIEW.load(Ordering::Relaxed) {
        1 => EcosystemView::Swap, 2 => EcosystemView::NodeSettings, _ => EcosystemView::Main,
    }
}
