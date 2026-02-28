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

use super::types::Platform;

pub fn detect_platform() -> Platform {
    const QEMU_SIG_EBX: u32 = 0x5447_4354;
    const QEMU_SIG_ECX: u32 = 0x5447_4354;
    const QEMU_SIG_EDX: u32 = 0x5447_4354;

    let cpuid_result = core::arch::x86_64::__cpuid(0x4000_0000);

    if cpuid_result.ebx == QEMU_SIG_EBX
        && cpuid_result.ecx == QEMU_SIG_ECX
        && cpuid_result.edx == QEMU_SIG_EDX
    {
        return Platform::Qemu;
    }

    if cpuid_result.eax >= 0x4000_0000 {
        return Platform::VirtualMachine;
    }

    Platform::BareMetal
}
