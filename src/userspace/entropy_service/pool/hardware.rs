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

use super::state::add_entropy;

pub(crate) fn add_hardware_entropy() {
    let rand = crate::security::crypto::random::secure_random_u64();
    add_entropy(&rand.to_le_bytes(), 64);
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    add_entropy(&tsc.to_le_bytes(), 2);
}

pub(crate) fn add_interrupt_entropy(irq: u8, timestamp: u64) {
    let data = [irq, (timestamp & 0xFF) as u8, ((timestamp >> 8) & 0xFF) as u8];
    add_entropy(&data, 1);
}
