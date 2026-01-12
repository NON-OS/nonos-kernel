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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::types::{MultibootError, MultibootInfo};

static TIMER_FREQ: AtomicU32 = AtomicU32::new(1000);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Qemu,
    VirtualMachine,
    BareMetal,
}

impl Platform {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Qemu => "QEMU",
            Self::VirtualMachine => "Virtual Machine",
            Self::BareMetal => "Bare Metal",
        }
    }

    #[inline]
    pub fn is_virtual(&self) -> bool {
        !matches!(self, Self::BareMetal)
    }

    pub fn optimize_for_platform(&self) {
        match self {
            Self::Qemu => {
                crate::log::info!("Detected QEMU - applying virtualization optimizations");
            }
            Self::VirtualMachine => {
                crate::log::info!("Detected virtual machine - applying general VM optimizations");
            }
            Self::BareMetal => {
                crate::log::info!("Detected bare-metal hardware - applying hardware optimizations");
            }
        }
    }

    #[inline]
    pub fn timer_frequency(&self) -> u32 {
        match self {
            Self::Qemu => 1000,
            Self::VirtualMachine => 100,
            Self::BareMetal => 1000,
        }
    }

    #[inline]
    pub fn supports_virtio(&self) -> bool {
        matches!(self, Self::Qemu | Self::VirtualMachine)
    }

    #[inline]
    pub fn console_type(&self) -> ConsoleType {
        match self {
            Self::Qemu => ConsoleType::Serial,
            Self::VirtualMachine | Self::BareMetal => ConsoleType::Vga,
        }
    }
}

impl core::fmt::Display for Platform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleType {
    Vga,
    Serial,
    Framebuffer,
}

impl ConsoleType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Vga => "VGA",
            Self::Serial => "Serial",
            Self::Framebuffer => "Framebuffer",
        }
    }
}

impl core::fmt::Display for ConsoleType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn detect_platform() -> Platform {
    const QEMU_SIG_EBX: u32 = 0x5447_4354;
    const QEMU_SIG_ECX: u32 = 0x5447_4354;
    const QEMU_SIG_EDX: u32 = 0x5447_4354;
    // # SAFETY: CPUID is always safe on x86_64
    unsafe {
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
}

pub fn get_safe_memory_regions(
    platform: Platform,
    multiboot_info: &MultibootInfo,
) -> Vec<crate::memory::layout::Region> {
    let mut regions = Vec::new();
    for entry in &multiboot_info.memory_map {
        if entry.is_available() && entry.length >= 4096 && entry.base_addr >= 0x10_0000 {
            regions.push(crate::memory::layout::Region {
                start: entry.base_addr,
                end: entry.base_addr.saturating_add(entry.length),
                kind: crate::memory::layout::RegionKind::Usable,
            });
        }
    }

    if regions.is_empty() {
        let (start, end) = match platform {
            Platform::Qemu => (0x10_0000, 0x800_0000),
            Platform::VirtualMachine => (0x10_0000, 0x400_0000),
            Platform::BareMetal => (0x10_0000, 0x200_0000),
        };

        regions.push(crate::memory::layout::Region {
            start,
            end,
            kind: crate::memory::layout::RegionKind::Usable,
        });
    }

    regions
}

pub fn init_platform_features(platform: Platform) -> Result<(), MultibootError> {
    platform.optimize_for_platform();
    match platform {
        Platform::Qemu => init_qemu_features(),
        Platform::VirtualMachine => init_vm_features(),
        Platform::BareMetal => init_baremetal_features(),
    }

    Ok(())
}

fn init_qemu_features() {
    // # SAFETY: Port I/O to configure QEMU debug console and fw_cfg
    unsafe {
        use x86_64::instructions::port::Port;
      
        let mut debugcon = Port::<u8>::new(0xE9);
        debugcon.write(0x00);

        let mut fw_cfg_selector = Port::<u16>::new(0x510);
        fw_cfg_selector.write(0x0000);

        let cpuid = core::arch::x86_64::__cpuid(0x4000_0001);
        let kvm_features = cpuid.eax;
        if kvm_features & (1 << 0) != 0 {
            crate::log::info!("KVM paravirt clock available");
        }

        if kvm_features & (1 << 3) != 0 {
            crate::log::info!("KVM async page fault available");
        }

        if kvm_features & (1 << 9) != 0 {
            crate::log::info!("KVM paravirt TLB flush available");
        }
    }

    configure_vm_timers(1000);
    crate::log::info!("Initialized QEMU-specific features");
}

fn init_vm_features() {
    // # SAFETY: CPUID access for hypervisor feature detection
    unsafe {
        let cpuid = core::arch::x86_64::__cpuid(0x4000_0000);
        let max_leaf = cpuid.eax;
        if max_leaf >= 0x4000_0001 {
            let features = core::arch::x86_64::__cpuid(0x4000_0001);
            if features.eax & (1 << 0) != 0 {
                crate::log::info!("Hypervisor TSC frequency available");
            }
        }

        let sig_ebx = cpuid.ebx;
        let sig_ecx = cpuid.ecx;
        let sig_edx = cpuid.edx;
        if sig_ebx == 0x7263694D && sig_ecx == 0x666F736F && sig_edx == 0x76482074 {
            crate::log::info!("Hyper-V hypervisor detected");
        }

        if sig_ebx == 0x61774D56 && sig_ecx == 0x4D566572 && sig_edx == 0x65726177 {
            crate::log::info!("VMware hypervisor detected");
        }
    }

    configure_vm_timers(100);
    crate::log::info!("Initialized general VM features");
}

fn init_baremetal_features() {
    // # SAFETY: Hardware capability detection via CPUID
    unsafe {
        let cpuid = core::arch::x86_64::__cpuid(0x8000_0007);
        let power_features = cpuid.edx;
        if power_features & (1 << 8) != 0 {
            crate::log::info!("Invariant TSC available for timing");
        }

        let cpuid_perf = core::arch::x86_64::__cpuid(0x0A);
        let perf_version = cpuid_perf.eax & 0xFF;

        if perf_version > 0 {
            crate::log::info!("Hardware performance counters v{} available", perf_version);
        }

        let cpuid_thermal = core::arch::x86_64::__cpuid(0x06);
        if cpuid_thermal.eax & (1 << 0) != 0 {
            crate::log::info!("Digital thermal sensor available");
        }

        let cpuid_features = core::arch::x86_64::__cpuid(0x01);
        if cpuid_features.ecx & (1 << 30) != 0 {
            crate::log::info!("Hardware RDRAND available");
        }
        if cpuid_features.ebx & (1 << 18) != 0 {
            crate::log::info!("Hardware RDSEED available");
        }
    }

    configure_vm_timers(1000);
    crate::log::info!("Initialized bare-metal hardware features");
}

fn configure_vm_timers(frequency_hz: u32) {
    TIMER_FREQ.store(frequency_hz, Ordering::Relaxed);
}

pub(super) fn get_timer_frequency() -> u32 {
    TIMER_FREQ.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use super::super::types::MemoryMapEntry;
    use super::*;

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Qemu.as_str(), "QEMU");
        assert_eq!(Platform::VirtualMachine.as_str(), "Virtual Machine");
        assert_eq!(Platform::BareMetal.as_str(), "Bare Metal");
    }

    #[test]
    fn test_platform_is_virtual() {
        assert!(Platform::Qemu.is_virtual());
        assert!(Platform::VirtualMachine.is_virtual());
        assert!(!Platform::BareMetal.is_virtual());
    }

    #[test]
    fn test_platform_virtio_support() {
        assert!(Platform::Qemu.supports_virtio());
        assert!(Platform::VirtualMachine.supports_virtio());
        assert!(!Platform::BareMetal.supports_virtio());
    }

    #[test]
    fn test_console_type_display() {
        assert_eq!(ConsoleType::Serial.as_str(), "Serial");
        assert_eq!(ConsoleType::Vga.as_str(), "VGA");
        assert_eq!(ConsoleType::Framebuffer.as_str(), "Framebuffer");
    }

    #[test]
    fn test_get_safe_memory_fallback() {
        let empty_info = MultibootInfo {
            memory_map: vec![],
            framebuffer_info: None,
            module_info: None,
        };

        let regions = get_safe_memory_regions(Platform::Qemu, &empty_info);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].start, 0x10_0000);
        assert_eq!(regions[0].end, 0x800_0000);
    }
}
