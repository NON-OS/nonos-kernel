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

// Early-debug console transport. Every supported architecture has one
// before kernel-core init runs.
//
// `LegacySerial` carries an x86 IO-port base (0x3F8 for COM1). `Uart`
// carries a memory-mapped UART base (PL011 on aarch64, NS16550 on
// riscv64).

#[derive(Debug, Clone, Copy)]
pub enum EarlyConsole {
    LegacySerial(u16),
    Uart(u64),
}
