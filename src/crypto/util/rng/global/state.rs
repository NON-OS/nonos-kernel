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

use core::sync::atomic::AtomicU8;
use spin::Mutex;
use super::super::csprng::ChaChaRng;

pub(crate) const STATE_UNINITIALIZED: u8 = 0;
pub(crate) const STATE_INITIALIZING: u8 = 1;
pub(crate) const STATE_INITIALIZED: u8 = 2;

pub(crate) static GLOBAL_STATE: AtomicU8 = AtomicU8::new(STATE_UNINITIALIZED);

pub static GLOBAL_COUNTER: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

pub(crate) static GLOBAL_RNG: Mutex<Option<ChaChaRng>> = Mutex::new(None);
