#![no_std]

use alloc::{collections::BTreeMap, vec::Vec};
use core::arch::asm;
use spin::{Mutex, Once};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::nonos_frame_alloc as frame_alloc;
use crate::memory::nonos_layout as layout;

pub struct MMU {
    current_cr3: Mutex<u64>,
    page_tables: Mutex<BTreeMap<u64, PageTableEntry>>,
    protection_flags: Mutex<ProtectionFlags>,
    initialized: Mutex<bool>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProtectionFlags {
    pub smep_enabled: bool,
    pub smap_enabled: bool,
    pub nx_enabled: bool,
    pub wp_enabled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry {
    pub present: bool,
    pub writable: bool,
    pub user_accessible: bool,
    pub write_through: bool,
    pub cache_disabled: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub huge_page: bool,
    pub global: bool,
    pub no_execute: bool,
    pub physical_address: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct PagePermissions {
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
    pub cache_disabled: bool,
}

impl MMU {
    pub const fn new() -> Self {
        Self {
            current_cr3: Mutex::new(0),
            page_tables: Mutex::new(BTreeMap::new()),
            protection_flags: Mutex::new(ProtectionFlags {
                smep_enabled: false,
                smap_enabled: false,
                nx_enabled: false,
                wp_enabled: true,
            }),
            initialized: Mutex::new(false),
        }
    }

    pub fn initialize(&self) -> Result<(), &'static str> {
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

    fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
        // Returns (EAX, EBX, ECX, EDX)
        let mut eax = leaf;
        let mut ebx: u32;
        let mut ecx = subleaf;
        let mut edx: u32;
        unsafe {
            asm!(
                "push rbx",
                "cpuid",
                "mov {0:e}, ebx",
                "pop rbx",
                out(reg) ebx,
                inout("eax") eax, 
                inout("ecx") ecx, 
                out("edx") edx,
                options(nostack, preserves_flags)
            );
        }
        (eax, ebx, ecx, edx)
    }

    /// Enable SMEP/SMAP in CR4 if supported by CPUID(7,0).EBX
    fn enable_smep_smap(&self) -> Result<(), &'static str> {
        let (_a, ebx, _c, _d) = MMU::cpuid(0x07, 0x00);
        let has_smep = (ebx & (1 << 7)) != 0;
        let has_smap = (ebx & (1 << 20)) != 0;

        unsafe {
            // Read CR4
            let mut cr4: u64;
            asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));

            if has_smep {
                cr4 |= 1 << 20;
            }
            if has_smap {
                cr4 |= 1 << 21;
            }

            asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        }

        let mut flags = self.protection_flags.lock();
        flags.smep_enabled = has_smep;
        flags.smap_enabled = has_smap;

        Ok(())
    }

    /// Ensure IA32_EFER.NXE (bit 11) is set if NX supported by CPUID(0x80000001).EDX bit 20.
    fn enable_nx_bit(&self) -> Result<(), &'static str> {
        let (_a, _b, _c, edx) = MMU::cpuid(0x8000_0001, 0);
        let nx_supported = (edx & (1 << 20)) != 0;
        if !nx_supported {
            return Err("NXE not supported by CPU");
        }

        // IA32_EFER MSR = 0xC000_0080
        const IA32_EFER: u32 = 0xC000_0080;
        unsafe {
            let mut eax: u32;
            let mut edx: u32;
            asm!(
                "rdmsr",
                in("ecx") IA32_EFER,
                out("eax") eax, out("edx") edx,
                options(nostack, preserves_flags)
            );
            let mut efer = ((edx as u64) << 32) | (eax as u64);
            efer |= 1 << 11; // NXE
            let eax2 = (efer & 0xFFFF_FFFF) as u32;
            let edx2 = (efer >> 32) as u32;
            asm!(
                "wrmsr",
                in("ecx") IA32_EFER,
                in("eax") eax2, in("edx") edx2,
                options(nostack, preserves_flags)
            );
        }

        self.protection_flags.lock().nx_enabled = true;
        Ok(())
    }

    /// Allocate a blank PML4 and minimally load it into CR3 (no mappings done here).
    fn setup_initial_page_tables(&self) -> Result<(), &'static str> {
        let pml4 = self.allocate_page_table_frame()?;
        // Zero the PML4
        let pml4_va = self.frame_to_virt(pml4);
        unsafe {
            core::ptr::write_bytes(pml4_va.as_mut_ptr::<u64>(), 0, 512);
        }
        self.load_page_table(pml4)?;
        Ok(())
    }

    /// Map a virtual range with given permissions using a raw 4-level walk.
    /// Intended for early boot/platform bring-up. Prefer memory::virt for normal use.
    fn map_memory_range(
        &self,
        pml4_virt: VirtAddr,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        permissions: PagePermissions,
    ) -> Result<(), &'static str> {
        let page_size = 4096usize;
        let pages = (size + page_size - 1) / page_size;
        for i in 0..pages {
            let va = VirtAddr::new(virt_start.as_u64() + (i * page_size) as u64);
            let pa = PhysAddr::new(phys_start.as_u64() + (i * page_size) as u64);
            self.map_single_page(pml4_virt, va, pa, permissions)?;
        }
        Ok(())
    }

    /// Map a single 4 KiB page by building intermediate tables as needed.
    fn map_single_page(
        &self,
        pml4_virt: VirtAddr,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        permissions: PagePermissions,
    ) -> Result<(), &'static str> {
        let pml4_index = (virt_addr.as_u64() >> 39) & 0x1FF;
        let pdpt_index = (virt_addr.as_u64() >> 30) & 0x1FF;
        let pd_index = (virt_addr.as_u64() >> 21) & 0x1FF;
        let pt_index = (virt_addr.as_u64() >> 12) & 0x1FF;

        unsafe {
            // PML4
            let pml4_table = pml4_virt.as_mut_ptr::<u64>();
            let pml4_entry_ptr: *mut u64 = pml4_table.add(pml4_index as usize);
            let pdpt_phys = if (*pml4_entry_ptr & 1) == 0 {
                let f = self.allocate_page_table_frame()?;
                let v = self.frame_to_virt(f);
                core::ptr::write_bytes(v.as_mut_ptr::<u64>(), 0, 512);
                *pml4_entry_ptr = f.as_u64() | 0x3; // Present|Writable
                f
            } else {
                PhysAddr::new(*pml4_entry_ptr & 0x000F_FFFF_FFFF_F000)
            };

            // PDPT
            let pdpt_virt = self.frame_to_virt(pdpt_phys);
            let pdpt_entry_ptr = pdpt_virt.as_ptr::<u64>().add(pdpt_index as usize) as *mut u64;
            let pd_phys = if (*pdpt_entry_ptr & 1) == 0 {
                let f = self.allocate_page_table_frame()?;
                let v = self.frame_to_virt(f);
                core::ptr::write_bytes(v.as_mut_ptr::<u64>(), 0, 512);
                *pdpt_entry_ptr = f.as_u64() | 0x3;
                f
            } else {
                PhysAddr::new(*pdpt_entry_ptr & 0x000F_FFFF_FFFF_F000)
            };

            // PD
            let pd_virt = self.frame_to_virt(pd_phys);
            let pd_entry_ptr = pd_virt.as_ptr::<u64>().add(pd_index as usize) as *mut u64;
            let pt_phys = if (*pd_entry_ptr & 1) == 0 {
                let f = self.allocate_page_table_frame()?;
                let v = self.frame_to_virt(f);
                core::ptr::write_bytes(v.as_mut_ptr::<u64>(), 0, 512);
                *pd_entry_ptr = f.as_u64() | 0x3;
                f
            } else {
                PhysAddr::new(*pd_entry_ptr & 0x000F_FFFF_FFFF_F000)
            };

            // PT
            let pt_virt = self.frame_to_virt(pt_phys);
            let pt_entry_ptr = pt_virt.as_ptr::<u64>().add(pt_index as usize) as *mut u64;

            // Enforce W^X: if executable, cannot be writable
            if permissions.executable && permissions.writable {
                return Err("W^X violation: requested RW+X");
            }

            let mut entry = phys_addr.as_u64() | 1; // Present
            if permissions.writable { entry |= 1 << 1; }       // W
            if permissions.user_accessible { entry |= 1 << 2; } // U/S
            if permissions.cache_disabled { entry |= 1 << 4; }  // PCD
            if !permissions.executable { entry |= 1u64 << 63; } // NX

            *pt_entry_ptr = entry;
        }

        let mut cache = self.page_tables.lock();
        cache.insert(
            virt_addr.as_u64(),
            PageTableEntry {
                present: true,
                writable: permissions.writable,
                user_accessible: permissions.user_accessible,
                write_through: false,
                cache_disabled: permissions.cache_disabled,
                accessed: false,
                dirty: false,
                huge_page: false,
                global: false,
                no_execute: !permissions.executable,
                physical_address: phys_addr.as_u64(),
            },
        );

        Ok(())
    }

    fn load_page_table(&self, pml4_frame: PhysAddr) -> Result<(), &'static str> {
        unsafe {
            asm!("mov cr3, {}", in(reg) pml4_frame.as_u64(), options(nostack, preserves_flags));
        }
        *self.current_cr3.lock() = pml4_frame.as_u64();
        self.invalidate_tlb_all();
        crate::log::logger::log_info!("CR3 <- {:#x}", pml4_frame.as_u64());
        Ok(())
    }

    pub fn invalidate_tlb_all(&self) {
        unsafe {
            let cr3: u64;
            asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
            asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
        }
    }

    pub fn invalidate_tlb_page(&self, virt_addr: VirtAddr) {
        unsafe { 
            asm!("invlpg [{}]", in(reg) virt_addr.as_u64(), options(nostack, preserves_flags)) 
        }
    }

    fn allocate_page_table_frame(&self) -> Result<PhysAddr, &'static str> {
        frame_alloc::allocate_frame().ok_or("Failed to allocate page table frame")
    }

    #[inline]
    fn frame_to_virt(&self, frame: PhysAddr) -> VirtAddr {
        VirtAddr::new(layout::DIRECTMAP_BASE + frame.as_u64())
    }

    /// Update permissions of an existing mapping. Enforces W^X.
    pub fn change_page_protection(
        &self,
        virt_addr: VirtAddr,
        new_permissions: PagePermissions,
    ) -> Result<(), &'static str> {
        if new_permissions.executable && new_permissions.writable {
            return Err("W^X violation: RW+X not allowed");
        }

        let cr3 = *self.current_cr3.lock();
        if cr3 == 0 {
            return Err("CR3 not initialized");
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
    ) -> Result<(), &'static str> {
        let pml4_index = (virt_addr.as_u64() >> 39) & 0x1FF;
        let pdpt_index = (virt_addr.as_u64() >> 30) & 0x1FF;
        let pd_index = (virt_addr.as_u64() >> 21) & 0x1FF;
        let pt_index = (virt_addr.as_u64() >> 12) & 0x1FF;

        unsafe {
            // Walk tables
            let pml4_table = pml4_virt.as_ptr::<u64>();
            let pml4_entry = *pml4_table.add(pml4_index as usize);
            if (pml4_entry & 1) == 0 { return Err("Not mapped"); }

            let pdpt_virt = self.frame_to_virt(PhysAddr::new(pml4_entry & 0x000F_FFFF_FFFF_F000));
            let pdpt_entry = *pdpt_virt.as_ptr::<u64>().add(pdpt_index as usize);
            if (pdpt_entry & 1) == 0 { return Err("Not mapped"); }

            let pd_virt = self.frame_to_virt(PhysAddr::new(pdpt_entry & 0x000F_FFFF_FFFF_F000));
            let pd_entry = *pd_virt.as_ptr::<u64>().add(pd_index as usize);
            if (pd_entry & 1) == 0 { return Err("Not mapped"); }

            let pt_virt = self.frame_to_virt(PhysAddr::new(pd_entry & 0x000F_FFFF_FFFF_F000));
            let pt_entry_ptr = pt_virt.as_ptr::<u64>().add(pt_index as usize) as *mut u64;
            let old_entry = *pt_entry_ptr;
            if (old_entry & 1) == 0 { return Err("Not mapped"); }

            // Enforce W^X again here
            if permissions.executable && permissions.writable {
                return Err("W^X violation: RW+X not allowed");
            }

            let phys = old_entry & 0x000F_FFFF_FFFF_F000;
            let mut new_entry = phys | 1;
            if permissions.writable { new_entry |= 1 << 1; }
            if permissions.user_accessible { new_entry |= 1 << 2; }
            if permissions.cache_disabled { new_entry |= 1 << 4; }
            if !permissions.executable { new_entry |= 1u64 << 63; }

            *pt_entry_ptr = new_entry;
        }

        Ok(())
    }

    pub fn get_current_cr3(&self) -> u64 {
        *self.current_cr3.lock()
    }

    pub fn is_initialized(&self) -> bool {
        *self.initialized.lock()
    }

    pub fn map_kernel_range(&self, virt_start: VirtAddr, phys_start: PhysAddr, size: usize, permissions: PagePermissions) -> Result<(), &'static str> {
        if !self.is_initialized() {
            return Err("MMU not initialized");
        }
        
        let cr3 = self.get_current_cr3();
        if cr3 == 0 {
            return Err("No page table loaded");
        }
        
        let pml4_virt = self.frame_to_virt(PhysAddr::new(cr3));
        self.map_memory_range(pml4_virt, virt_start, phys_start, size, permissions)
    }
}

static MMU_INSTANCE: Once<MMU> = Once::new();

pub fn init_mmu() -> Result<(), &'static str> {
    let mmu = MMU_INSTANCE.call_once(MMU::new);
    mmu.initialize()
}

pub fn get_mmu() -> Result<&'static MMU, &'static str> {
    MMU_INSTANCE.get().ok_or("MMU not initialized")
}

pub fn map_kernel_memory(virt_start: VirtAddr, phys_start: PhysAddr, size: usize, writable: bool, executable: bool) -> Result<(), &'static str> {
    let mmu = get_mmu()?;
    let permissions = PagePermissions {
        writable,
        user_accessible: false,
        executable,
        cache_disabled: false,
    };
    
    let cr3 = mmu.get_current_cr3();
    if cr3 == 0 {
        return Err("No page table loaded");
    }
    
    let pml4_virt = mmu.frame_to_virt(PhysAddr::new(cr3));
    mmu.map_memory_range(pml4_virt, virt_start, phys_start, size, permissions)
}

pub fn invalidate_page(addr: VirtAddr) -> Result<(), &'static str> {
    get_mmu()?.invalidate_tlb_page(addr);
    Ok(())
}

pub fn current_cr3() -> Result<u64, &'static str> {
    Ok(get_mmu()?.get_current_cr3())
}
