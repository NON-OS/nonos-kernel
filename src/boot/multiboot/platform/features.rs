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

use core::sync::atomic::{AtomicU32, Ordering};

use super::super::types::MultibootError;
use super::types::Platform;

static TIMER_FREQ: AtomicU32 = AtomicU32::new(1000);

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
    // SAFETY: Port I/O to configure QEMU debug console and fw_cfg
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

    configure_vm_timers(100);
    crate::log::info!("Initialized general VM features");
}

fn init_baremetal_features() {
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

    configure_vm_timers(1000);
    crate::log::info!("Initialized bare-metal hardware features");
}

fn configure_vm_timers(frequency_hz: u32) {
    TIMER_FREQ.store(frequency_hz, Ordering::Relaxed);
}
