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

//! `Driver` is the binding from a successful `setup::run` to the
//! main loop: PIO grant id used for every port access plus IRQ
//! grant ids used to acknowledge keyboard and AUX mouse interrupts.

pub struct Driver {
    pub pio_grant_id: u64,
    pub irq_grant_id: u64,
    pub aux_irq_grant_id: u64,
    pub mouse_enabled: bool,
}
