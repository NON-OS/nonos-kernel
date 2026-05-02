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

#[derive(Debug, Clone, Copy)]
pub enum TrapCause {
    PageFault(PageFaultInfo),
    ProtectionFault { error_code: u64 },
    StackSegment { error_code: u64 },
    SegmentNotPresent { error_code: u64 },
    InvalidTss { error_code: u64 },
    InvalidOpcode,
    Alignment,
    DivideError,
    Overflow,
    BoundRange,
    DeviceNotAvailable,
    X87FloatingPoint,
    SimdFloatingPoint,
    Virtualization,
    ControlProtection { error_code: u64 },
    DoubleFault { error_code: u64 },
    MachineCheck,
    Nmi,
    OtherException(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct PageFaultInfo {
    pub fault_address: u64,
    pub access: FaultAccess,
    pub present: bool,
    pub user: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAccess {
    Read,
    Write,
    InstructionFetch,
}
