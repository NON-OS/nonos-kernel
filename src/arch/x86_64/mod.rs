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

extern crate alloc;

pub mod acpi;
mod api;
pub mod boot;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod interrupt;
#[cfg(feature = "nonos-arch-iommu")]
pub mod iommu;
// PS/2 + USB HID keyboard subtree. Not on the microkernel boot path
// (no input capsule yet); off in microkernel-core.
pub mod multiboot;
pub mod pci;
pub mod port;
#[cfg(feature = "nonos-arch-hardening")]
pub mod security;
pub mod serial;
pub mod smm;
pub mod syscall;
pub mod time;
pub mod uefi;
pub mod vga;
pub mod watchdog;

pub use api::{get_stats, init, init_with_acpi, is_initialized, ArchStats};

pub use gdt::{
    IST_DEBUG, IST_DOUBLE_FAULT, IST_GP, IST_MACHINE_CHECK, IST_NMI, IST_PAGE_FAULT,
    SEL_KERNEL_CODE, SEL_KERNEL_DATA, SEL_NULL, SEL_TSS, SEL_USER_CODE, SEL_USER_DATA,
};

pub use idt::{
    are_enabled, disable, enable, without_interrupts, InterruptFrame, IRQ_BASE, VEC_BREAKPOINT,
    VEC_DEBUG, VEC_DIVIDE_ERROR, VEC_DOUBLE_FAULT, VEC_GENERAL_PROTECTION, VEC_NMI, VEC_PAGE_FAULT,
};

pub use x86_64::structures::idt::InterruptStackFrame;

pub use cpu::{cli, hlt, lfence, mfence, pause, rdtsc, sfence, sti};
pub use port::{inb, inl, inw, outb, outl, outw, Port};
pub use serial::{write_str as serial_write_str, SerialWriter};
pub use time::{delay_ms, delay_ns, delay_us, now_ns};
pub use vga::{clear, print_critical, set_color, write_byte, write_str, Color, ColorCode};

#[cfg(feature = "nonos-arch-iommu")]
pub use iommu::{
    allocate_domain, disable as iommu_disable, enable as iommu_enable, flush_iotlb,
    flush_iotlb_all, flush_iotlb_page, free_domain, get_device_domain,
    get_stats as iommu_get_stats, get_unit_stats, init as iommu_init, is_device_mapped,
    is_enabled as iommu_is_enabled, is_initialized as iommu_is_initialized, map_device,
    map_page as iommu_map_page, map_range as iommu_map_range, translate as iommu_translate,
    unit_count as iommu_unit_count, unmap_device, unmap_page as iommu_unmap_page,
    unmap_range as iommu_unmap_range, DmarTable, Domain, DomainId, IntelVtd, IommuCapabilities,
    IommuError, IommuExtendedCapabilities, IommuFault, IommuPageFlags, IommuPageTable, IommuStats,
    IommuType, IommuUnit, UnitStats,
};

#[cfg(feature = "nonos-arch-hardening")]
pub use security::{
    detect_vulnerabilities, disable_ibrs, disable_ssbd, disable_stibp, enable_ibrs, enable_ssbd,
    enable_stibp, ibpb, is_ibpb_supported, is_ibrs_supported, is_ssbd_supported,
    is_stibp_supported, map_kernel_to_user, retpoline_call, setup_user_page_table,
    switch_to_kernel, switch_to_user, unmap_kernel_from_user, SpectreVulnerabilities,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ist_constants() {
        assert!(IST_DOUBLE_FAULT > 0);
        assert!(IST_NMI > 0);
    }

    #[test]
    fn test_segment_selectors() {
        assert_eq!(SEL_NULL, 0);
        assert!(SEL_KERNEL_CODE > 0);
    }

    #[test]
    fn test_irq_base() {
        assert_eq!(IRQ_BASE, 32);
    }
}
