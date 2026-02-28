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

pub const IA32_APIC_BASE: u32 = 0x1B;
pub const IA32_TSC_DEADLINE: u32 = 0x6E0;
pub const IA32_X2APIC_APICID: u32 = 0x802;
pub const IA32_X2APIC_TPR: u32 = 0x808;
pub const IA32_X2APIC_EOI: u32 = 0x80B;
pub const IA32_X2APIC_SVR: u32 = 0x80F;
pub const IA32_X2APIC_ICR: u32 = 0x830;
pub const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
pub const IA32_X2APIC_LVT_THERM: u32 = 0x833;
pub const IA32_X2APIC_LVT_LINT0: u32 = 0x835;
pub const IA32_X2APIC_LVT_LINT1: u32 = 0x836;
pub const IA32_X2APIC_LVT_ERROR: u32 = 0x837;
pub const IA32_X2APIC_DIV: u32 = 0x83E;
pub const IA32_X2APIC_INITCNT: u32 = 0x838;
pub const IA32_X2APIC_CURRCNT: u32 = 0x839;

pub const LAPIC_ID: u32 = 0x020;
pub const LAPIC_VER: u32 = 0x030;
pub const LAPIC_TPR: u32 = 0x080;
pub const LAPIC_EOI: u32 = 0x0B0;
pub const LAPIC_SVR: u32 = 0x0F0;
pub const LAPIC_ICR_LOW: u32 = 0x300;
pub const LAPIC_ICR_HIGH: u32 = 0x310;
pub const LAPIC_LVT_TIMER: u32 = 0x320;
pub const LAPIC_LVT_THERM: u32 = 0x330;
pub const LAPIC_LVT_LINT0: u32 = 0x350;
pub const LAPIC_LVT_LINT1: u32 = 0x360;
pub const LAPIC_LVT_ERROR: u32 = 0x370;
pub const LAPIC_INITCNT: u32 = 0x380;
pub const LAPIC_CURRCNT: u32 = 0x390;
pub const LAPIC_DIV: u32 = 0x3E0;

pub const APIC_BASE_ENABLE: u64 = 1 << 11;
pub const APIC_BASE_X2: u64 = 1 << 10;
pub const SVR_APIC_ENABLE: u32 = 1 << 8;
pub const SVR_EOI_SUPPRESS: u32 = 1 << 12;

pub const LVT_MASKED: u32 = 1 << 16;
pub const LVT_LEVEL: u32 = 1 << 15;
pub const LVT_NMI: u32 = 0b100 << 8;
pub const LVT_FIXED: u32 = 0b000 << 8;
pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
pub const LVT_TIMER_TSC_DEADLINE: u32 = 2 << 17;

pub const ICR_DELIV_FIXED: u64 = 0x0 << 8;
pub const ICR_DELIV_SIPI: u64 = 0x6 << 8;
pub const ICR_DELIV_INIT: u64 = 0x5 << 8;
pub const ICR_DST_PHYSICAL: u64 = 0 << 11;
pub const ICR_LEVEL_ASSERT: u64 = 1 << 14;
pub const ICR_LEVEL_DEASSERT: u64 = 0 << 14;
pub const ICR_TRIG_EDGE: u64 = 0 << 15;
pub const ICR_SH_NONE: u64 = 0b00 << 18;
pub const ICR_SH_SELF: u64 = 0b01 << 18;
pub const ICR_SH_ALL: u64 = 0b10 << 18;
pub const ICR_SH_OTHERS: u64 = 0b11 << 18;
pub const ICR_BUSY: u32 = 1 << 12;

pub const VEC_SPURIOUS: u8 = 0xFF;
pub const VEC_TIMER: u8 = 0x20;
pub const VEC_THERMAL: u8 = 0x21;
pub const VEC_ERROR: u8 = 0x22;
