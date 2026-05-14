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

use super::super::constants::MAX_GSI;

pub(super) const OWNER_FREE: u8 = 0;
pub(super) const OWNER_KERNEL: u8 = 1;
pub(super) const OWNER_CAPSULE: u8 = 2;

const INIT: AtomicU8 = AtomicU8::new(OWNER_FREE);

// Per-GSI owner byte. One static table sized to the largest GSI the
// IO-APIC layer addresses; updates use CAS so the broker's bind path
// and any future kernel claim race safely.
pub(super) static GSI_OWNERS: [AtomicU8; MAX_GSI] = [INIT; MAX_GSI];
