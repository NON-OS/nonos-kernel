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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KernelComponent {
    Memory = 0,
    Scheduler = 1,
    Ipc = 2,
    Capabilities = 3,
    Interrupts = 4,
    Syscall = 5,
    Process = 6,
    Arch = 7,
    Boot = 8,
    Context = 9,
    Usercopy = 10,
    Smp = 11,
}

impl KernelComponent {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Scheduler => "sched",
            Self::Ipc => "ipc",
            Self::Capabilities => "capabilities",
            Self::Interrupts => "interrupts",
            Self::Syscall => "syscall",
            Self::Process => "process",
            Self::Arch => "arch",
            Self::Boot => "boot",
            Self::Context => "context",
            Self::Usercopy => "usercopy",
            Self::Smp => "smp",
        }
    }
}

pub const KERNEL_MODULES: &[&str] = &[
    "memory",
    "sched",
    "ipc",
    "capabilities",
    "interrupts",
    "syscall",
    "process",
    "arch",
    "boot",
    "context",
    "usercopy",
    "smp",
    "elf",
    "bus",
];

pub fn is_kernel_component(name: &str) -> bool {
    matches!(
        name,
        "memory"
            | "sched"
            | "ipc"
            | "capabilities"
            | "interrupts"
            | "syscall"
            | "process"
            | "arch"
            | "boot"
            | "context"
            | "usercopy"
            | "smp"
            | "elf"
            | "bus"
    )
}
