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

//! ERDP write-1-to-clear bit. EHB is the Event Handler Busy
//! latch the controller sets when the IRQ line goes high; the
//! capsule clears it after each pass over the event ring so the
//! next IRQ-line transition is observable. DESI (the active ERST
//! segment index) is always 0 in P0 — single-segment event ring —
//! so the field is implicit and not surfaced as a constant.

pub const ERDP_EHB: u64 = 1 << 3;
