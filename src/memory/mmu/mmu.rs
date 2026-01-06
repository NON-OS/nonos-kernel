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
use alloc::collections::BTreeMap;
use core::arch::asm;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
use super::error::{MmuError, MmuResult};
use super::types::{PagePermissions, PageTableEntry, ProtectionFlags};
use crate::memory::{frame_alloc, layout};
// ============================================================================
// MMU STRUCTURE
// ============================================================================
pub struct MMU {
    current_cr3: Mutex<u64>,
    page_tables: Mutex<BTreeMap<u64, PageTableEntry>>,
    protection_flags: Mutex<ProtectionFlags>,
    initialized: Mutex<bool>,
}

impl MMU {
    pub const fn new() -> Self {
        Self {
            current_cr3: Mutex::new(0),
            page_tables: Mutex::new(BTreeMap::new()),
            protection_flags: Mutex::new(ProtectionFlags::new()),
            initialized: Mutex::new(false),
        }
    }

    /// Initializes the MMU.
    pub fn initialize(&self) -> MmuResult<()> {
        let mut init_guard = self.initialized.lock();
        if *init_guard {
            return Ok(());
        }

        self.enable_smep_smap()?;
        self.enable_nx_bit()?;
        let cr3_guard = self.current_cr3.lock();
        if *cr3_guard == 0 {
            drop(cr3_guard);
            self.setup_initial_page_tables()?;
        }

        *init_guard = true;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        *self.initialized.lock()
    }

    pub fn get_current_cr3(&self) -> u64 {
        *self.current_cr3.lock()
    }

    pub fn get_protection_flags(&self) -> ProtectionFlags {
        *self.protection_flags.lock()
    }

    // ========================================================================
    // CPU FEATURE CONFIGURATION
    // ========================================================================

    /// Enables SMEP and SMAP if supported.
    fn enable_smep_smap(&self) -> MmuResult<()> {
        let (_, ebx, _, _) = Self::cpuid(CPUID_FEATURES_LEAF, 0);
        let has_smep = (ebx & CPUID_EBX_SMEP) != 0;
        let has_smap = (ebx & CPUID_EBX_SMAP) != 0;
        // SAFETY: Modifying CR4 to enable security features
        unsafe {
            let mut cr4: u64;
            asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
            if has_smep {
                cr4 |= CR4_SMEP;
            }
            if has_smap {
                cr4 |= CR4_SMAP;
            }
            asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        }

        let mut flags = self.protection_flags.lock();
        flags.smep_enabled = has_smep;
        flags.smap_enabled = has_smap;
        Ok(())
    }

    fn enable_nx_bit(&self) -> MmuResult<()> {
        let (_, _, _, edx) = Self::cpuid(CPUID_EXTENDED_LEAF, 0);
        let nx_supported = (edx & CPUID_EDX_NX) != 0;
        if !nx_supported {
            return Err(MmuError::NxNotSupported);
        }

        // SAFETY: Reading and writing IA32_EFER MSR
        unsafe {
            let mut eax: u32;
            let mut edx: u32;
            asm!(
                "rdmsr",
                in("ecx") MSR_IA32_EFER,
                out("eax") eax,
                out("edx") edx,
                options(nostack, preserves_flags)
            );

            let mut efer = ((edx as u64) << 32) | (eax as u64);
            efer |= EFER_NXE;
            let eax2 = (efer & 0xFFFF_FFFF) as u32;
            let edx2 = (efer >> 32) as u32;
            asm!(
                "wrmsr",
                in("ecx") MSR_IA32_EFER,
                in("eax") eax2,
                in("edx") edx2,
                options(nostack, preserves_flags)
            );
        }

        self.protection_flags.lock().nx_enabled = true;
        Ok(())
    }

    fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
        // SAFETY: CPUID is always safe to execute
        let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
        (result.eax, result.ebx, result.ecx, result.edx)
    }
    // ========================================================================
    // PAGE TABLE SETUP
    // ========================================================================
    fn setup_initial_page_tables(&self) -> MmuResult<()> {
        let pml4 = self.allocate_page_table_frame()?;
        let pml4_va = self.frame_to_virt(pml4);
        // SAFETY: Zeroing newly allocated page table
        unsafe {
            core::ptr::write_bytes(pml4_va.as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
        }

        self.load_page_table(pml4)?;
        Ok(())
    }

    fn load_page_table(&self, pml4_frame: PhysAddr) -> MmuResult<()> {
        // SAFETY: Loading valid page table into CR3
        unsafe {
            asm!(
                "mov cr3, {}",
                in(reg) pml4_frame.as_u64(),
                options(nostack, preserves_flags)
            );
        }

        *self.current_cr3.lock() = pml4_frame.as_u64();
        self.invalidate_tlb_all();
        Ok(())
    }

    fn allocate_page_table_frame(&self) -> MmuResult<PhysAddr> {
        frame_alloc::allocate_frame().ok_or(MmuError::FrameAllocationFailed)
    }

    #[inline]
    fn frame_to_virt(&self, frame: PhysAddr) -> VirtAddr {
        VirtAddr::new(layout::DIRECTMAP_BASE + frame.as_u64())
    }
    // ========================================================================
    // PAGE MAPPING
    // ========================================================================
    pub fn map_kernel_range(
        &self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        if !self.is_initialized() {
            return Err(MmuError::NotInitialized);
        }

        let cr3 = self.get_current_cr3();
        if cr3 == 0 {
            return Err(MmuError::NoPageTableLoaded);
        }

        let pml4_virt = self.frame_to_virt(PhysAddr::new(cr3));
        self.map_memory_range(pml4_virt, virt_start, phys_start, size, permissions)
    }

    fn map_memory_range(
        &self,
        pml4_virt: VirtAddr,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(virt_start.as_u64() + (i * PAGE_SIZE) as u64);
            let pa = PhysAddr::new(phys_start.as_u64() + (i * PAGE_SIZE) as u64);
            self.map_single_page(pml4_virt, va, pa, permissions)?;
        }

        Ok(())
    }

    fn map_single_page(
        &self,
        pml4_virt: VirtAddr,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        // Enforce W^X
        if permissions.is_wx_violation() {
            return Err(MmuError::WXViolation);
        }

        let pml4_idx = pml4_index(virt_addr.as_u64());
        let pdpt_idx = pdpt_index(virt_addr.as_u64());
        let pd_idx = pd_index(virt_addr.as_u64());
        let pt_idx = pt_index(virt_addr.as_u64());

        // SAFETY: Walking page tables with proper validation
        unsafe {
            let pml4_table = pml4_virt.as_mut_ptr::<u64>();
            let pml4_entry_ptr = pml4_table.add(pml4_idx);
            let pdpt_phys = if !pte_is_present(*pml4_entry_ptr) {
                let f = self.allocate_page_table_frame()?;
                let v = self.frame_to_virt(f);
                core::ptr::write_bytes(v.as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
                *pml4_entry_ptr = f.as_u64() | PTE_PRESENT | PTE_WRITABLE;
                f
            } else {
                PhysAddr::new(pte_address(*pml4_entry_ptr))
            };

            let pdpt_virt = self.frame_to_virt(pdpt_phys);
            let pdpt_entry_ptr = pdpt_virt.as_mut_ptr::<u64>().add(pdpt_idx);
            let pd_phys = if !pte_is_present(*pdpt_entry_ptr) {
                let f = self.allocate_page_table_frame()?;
                let v = self.frame_to_virt(f);
                core::ptr::write_bytes(v.as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
                *pdpt_entry_ptr = f.as_u64() | PTE_PRESENT | PTE_WRITABLE;
                f
            } else {
                PhysAddr::new(pte_address(*pdpt_entry_ptr))
            };

            let pd_virt = self.frame_to_virt(pd_phys);
            let pd_entry_ptr = pd_virt.as_mut_ptr::<u64>().add(pd_idx);
            let pt_phys = if !pte_is_present(*pd_entry_ptr) {
                let f = self.allocate_page_table_frame()?;
                let v = self.frame_to_virt(f);
                core::ptr::write_bytes(v.as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
                *pd_entry_ptr = f.as_u64() | PTE_PRESENT | PTE_WRITABLE;
                f
            } else {
                PhysAddr::new(pte_address(*pd_entry_ptr))
            };

            let pt_virt = self.frame_to_virt(pt_phys);
            let pt_entry_ptr = pt_virt.as_mut_ptr::<u64>().add(pt_idx);
            let pte = permissions.to_pte(phys_addr.as_u64());
            *pt_entry_ptr = pte.to_raw();
        }

        let pte = permissions.to_pte(phys_addr.as_u64());
        self.page_tables.lock().insert(virt_addr.as_u64(), pte);

        Ok(())
    }

    pub fn change_page_protection(
        &self,
        virt_addr: VirtAddr,
        new_permissions: PagePermissions,
    ) -> MmuResult<()> {
        if new_permissions.is_wx_violation() {
            return Err(MmuError::WXViolation);
        }

        let cr3 = self.get_current_cr3();
        if cr3 == 0 {
            return Err(MmuError::NoPageTableLoaded);
        }

        let pml4_virt = self.frame_to_virt(PhysAddr::new(cr3));
        self.update_page_entry(pml4_virt, virt_addr, new_permissions)?;
        self.invalidate_tlb_page(virt_addr);

        Ok(())
    }

    fn update_page_entry(
        &self,
        pml4_virt: VirtAddr,
        virt_addr: VirtAddr,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        if permissions.is_wx_violation() {
            return Err(MmuError::WXViolation);
        }

        let pml4_idx = pml4_index(virt_addr.as_u64());
        let pdpt_idx = pdpt_index(virt_addr.as_u64());
        let pd_idx = pd_index(virt_addr.as_u64());
        let pt_idx = pt_index(virt_addr.as_u64());
        // SAFETY: Walking page tables to update entry
        unsafe {
            let pml4_entry = *pml4_virt.as_ptr::<u64>().add(pml4_idx);
            if !pte_is_present(pml4_entry) {
                return Err(MmuError::NotMapped);
            }

            let pdpt_virt = self.frame_to_virt(PhysAddr::new(pte_address(pml4_entry)));
            let pdpt_entry = *pdpt_virt.as_ptr::<u64>().add(pdpt_idx);
            if !pte_is_present(pdpt_entry) {
                return Err(MmuError::NotMapped);
            }

            let pd_virt = self.frame_to_virt(PhysAddr::new(pte_address(pdpt_entry)));
            let pd_entry = *pd_virt.as_ptr::<u64>().add(pd_idx);
            if !pte_is_present(pd_entry) {
                return Err(MmuError::NotMapped);
            }

            let pt_virt = self.frame_to_virt(PhysAddr::new(pte_address(pd_entry)));
            let pt_entry_ptr = pt_virt.as_mut_ptr::<u64>().add(pt_idx);
            let old_entry = *pt_entry_ptr;
            if !pte_is_present(old_entry) {
                return Err(MmuError::NotMapped);
            }

            let phys = pte_address(old_entry);
            let pte = permissions.to_pte(phys);
            *pt_entry_ptr = pte.to_raw();
        }

        Ok(())
    }
    // ========================================================================
    // TLB MANAGEMENT
    // ========================================================================
    pub fn invalidate_tlb_all(&self) {
        // SAFETY: Reading and reloading CR3 flushes TLB
        unsafe {
            let cr3: u64;
            asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
            asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
        }
    }

    pub fn invalidate_tlb_page(&self, virt_addr: VirtAddr) {
        // SAFETY: INVLPG is safe
        unsafe {
            asm!(
                "invlpg [{}]",
                in(reg) virt_addr.as_u64(),
                options(nostack, preserves_flags)
            );
        }
    }
}

impl Default for MMU {
    fn default() -> Self {
        Self::new()
    }
}
// ============================================================================
// GLOBAL STATE
// ============================================================================
use spin::Once;
static MMU_INSTANCE: Once<MMU> = Once::new();
// ============================================================================
// PUBLIC API
// ============================================================================
pub fn init_mmu() -> MmuResult<()> {
    let mmu = MMU_INSTANCE.call_once(MMU::new);
    mmu.initialize()
}

pub fn get_mmu() -> MmuResult<&'static MMU> {
    MMU_INSTANCE.get().ok_or(MmuError::NotInitialized)
}

pub fn map_kernel_memory(
    virt_start: VirtAddr,
    phys_start: PhysAddr,
    size: usize,
    writable: bool,
    executable: bool,
) -> MmuResult<()> {
    let mmu = get_mmu()?;
    let permissions = PagePermissions {
        writable,
        user_accessible: false,
        executable,
        cache_disabled: false,
    };

    mmu.map_kernel_range(virt_start, phys_start, size, permissions)
}

pub fn invalidate_page(addr: VirtAddr) -> MmuResult<()> {
    get_mmu()?.invalidate_tlb_page(addr);
    Ok(())
}

pub fn current_cr3() -> MmuResult<u64> {
    Ok(get_mmu()?.get_current_cr3())
}

pub fn mmu_is_initialized() -> bool {
    MMU_INSTANCE.get().map(|m| m.is_initialized()).unwrap_or(false)
}

pub fn protection_flags() -> MmuResult<ProtectionFlags> {
    Ok(get_mmu()?.get_protection_flags())
}
