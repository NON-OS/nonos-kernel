// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

// Real .S files compiled into the bootloader image via
// `global_asm!`. AT&T syntax matches the GAS-style files; the
// symbols become `extern "C"` from the Rust side.

core::arch::global_asm!(include_str!("load_cr3.S"), options(att_syntax));
core::arch::global_asm!(include_str!("handoff_jump.S"), options(att_syntax));
core::arch::global_asm!(include_str!("com1_out.S"), options(att_syntax));
