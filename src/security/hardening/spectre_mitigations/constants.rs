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

pub(super) const MSR_IA32_SPEC_CTRL: u32 = 0x48;
pub(super) const MSR_IA32_PRED_CMD: u32 = 0x49;
pub(super) const MSR_IA32_FLUSH_CMD: u32 = 0x10B;
pub(super) const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x10A;

pub(super) const SPEC_CTRL_IBRS: u64 = 1 << 0;
pub(super) const SPEC_CTRL_STIBP: u64 = 1 << 1;
pub(super) const SPEC_CTRL_SSBD: u64 = 1 << 2;

pub(super) const PRED_CMD_IBPB: u64 = 1 << 0;

pub(super) const FLUSH_CMD_L1D: u64 = 1 << 0;

pub(super) const ARCH_CAP_RDCL_NO: u64 = 1 << 0;
pub(super) const ARCH_CAP_SSB_NO: u64 = 1 << 4;
pub(super) const ARCH_CAP_MDS_NO: u64 = 1 << 5;
pub(super) const ARCH_CAP_TAA_NO: u64 = 1 << 8;
pub(super) const ARCH_CAP_SBDR_SSDP_NO: u64 = 1 << 13;
