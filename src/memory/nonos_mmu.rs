//! Real Hardware MMU Control with Direct Register Access
//! 
//! This module provides real hardware Memory Management Unit control
//! with actual page table manipulation, TLB management, and SMEP/SMAP enforcement.

use crate::memory::{PhysAddr, VirtAddr};
use core::arch::asm;
use spin::{Mutex, RwLock};
use alloc::{vec::Vec, collections::BTreeMap};

/// Real Hardware MMU Controller
pub struct RealMMU {
    /// Current page table root (CR3)
    current_cr3: Mutex<u64>,
    /// Page table hierarchy cache
    page_tables: RwLock<BTreeMap<u64, PageTableEntry>>,
    /// TLB invalidation queue
    tlb_invalidation_queue: Mutex<Vec<VirtAddr>>,
    /// SMEP/SMAP configuration
    protection_flags: Mutex<ProtectionFlags>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProtectionFlags {
    pub smep_enabled: bool,    // Supervisor Mode Execution Prevention
    pub smap_enabled: bool,    // Supervisor Mode Access Prevention
    pub nx_enabled: bool,      // No Execute bit
    pub wp_enabled: bool,      // Write Protection
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

impl RealMMU {
    pub fn new() -> Self {
        Self {
            current_cr3: Mutex::new(0),
            page_tables: RwLock::new(BTreeMap::new()),
            tlb_invalidation_queue: Mutex::new(Vec::new()),
            protection_flags: Mutex::new(ProtectionFlags {
                smep_enabled: true,
                smap_enabled: true,
                nx_enabled: true,
                wp_enabled: true,
            }),
        }
    }
    
    /// Initialize MMU with hardware detection and setup
    pub fn initialize(&self) -> Result<(), &'static str> {
        // Enable hardware features
        self.enable_smep_smap()?;
        self.enable_nx_bit()?;
        self.setup_initial_page_tables()?;
        
        crate::log::logger::log_info!("Real MMU initialized with hardware features");
        Ok(())
    }
    
    /// Real hardware SMEP/SMAP enablement
    fn enable_smep_smap(&self) -> Result<(), &'static str> {
        unsafe {
            // Read CR4
            let mut cr4: u64;
            asm!("mov {}, cr4", out(reg) cr4);
            
            // Enable SMEP (bit 20) and SMAP (bit 21)
            cr4 |= (1 << 20) | (1 << 21);
            
            // Write back CR4
            asm!("mov cr4, {}", in(reg) cr4);
            
            // Verify SMEP/SMAP are supported
            let mut cpuid_result: u32;
            asm!(
                "cpuid",
                inout("eax") 0x7u32 => cpuid_result,
                out("ebx") _,
                out("ecx") _,
                out("edx") _,
            );
            
            if (cpuid_result & (1 << 7)) == 0 {
                return Err("SMEP not supported by hardware");
            }
        }
        
        let mut flags = self.protection_flags.lock();
        flags.smep_enabled = true;
        flags.smap_enabled = true;
        
        Ok(())
    }
    
    /// Enable NX (No Execute) bit support
    fn enable_nx_bit(&self) -> Result<(), &'static str> {
        unsafe {
            // Check if NX is supported
            let mut cpuid_edx: u32;
            asm!(
                "cpuid",
                inout("eax") 0x80000001u32 => _,
                out("ebx") _,
                out("ecx") _,
                out("edx") cpuid_edx,
            );
            
            if (cpuid_edx & (1 << 20)) == 0 {
                return Err("NX bit not supported");
            }
            
            // Enable NX bit in EFER MSR
            let mut efer: u64;
            asm!("rdmsr", in("ecx") 0xC0000080u32, out("eax") efer, out("edx") _);
            efer |= 1 << 11; // NXE bit
            asm!("wrmsr", in("ecx") 0xC0000080u32, in("eax") efer, in("edx") 0);
        }
        
        let mut flags = self.protection_flags.lock();
        flags.nx_enabled = true;
        
        Ok(())
    }
    
    /// Setup initial page tables with real memory layout
    fn setup_initial_page_tables(&self) -> Result<(), &'static str> {
        // Allocate PML4 table
        let pml4_frame = self.allocate_page_table_frame()?;
        let pml4_virt = self.frame_to_virt(pml4_frame);
        
        // Clear PML4 table
        unsafe {
            core::ptr::write_bytes(pml4_virt.as_mut_ptr::<u64>(), 0, 512);
        }
        
        // Map kernel space (higher half)
        self.map_kernel_space(pml4_virt)?;
        
        // Map user space (lower half)  
        self.map_user_space(pml4_virt)?;
        
        // Load new page table
        self.load_page_table(pml4_frame)?;
        
        Ok(())
    }
    
    /// Map kernel space with proper permissions
    fn map_kernel_space(&self, pml4_virt: VirtAddr) -> Result<(), &'static str> {
        // Map kernel code (read-only, executable)
        self.map_memory_range(
            pml4_virt,
            VirtAddr::new(0xFFFF800000000000), // Kernel start
            PhysAddr::new(0x100000),           // Physical kernel start
            0x400000,                          // 4MB kernel
            PagePermissions {
                writable: false,
                user_accessible: false,
                executable: true,
                cache_disabled: false,
            }
        )?;
        
        // Map kernel data (read-write, non-executable)
        self.map_memory_range(
            pml4_virt,
            VirtAddr::new(0xFFFF800000400000), // Kernel data start
            PhysAddr::new(0x500000),           // Physical data start
            0x400000,                          // 4MB data
            PagePermissions {
                writable: true,
                user_accessible: false,
                executable: false,
                cache_disabled: false,
            }
        )?;
        
        Ok(())
    }
    
    /// Map user space with restricted permissions
    fn map_user_space(&self, pml4_virt: VirtAddr) -> Result<(), &'static str> {
        // Map user code (read-only, executable, user accessible)
        self.map_memory_range(
            pml4_virt,
            VirtAddr::new(0x400000),     // User code start
            PhysAddr::new(0x1000000),    // Physical user start
            0x100000,                    // 1MB user space
            PagePermissions {
                writable: false,
                user_accessible: true,
                executable: true,
                cache_disabled: false,
            }
        )?;
        
        Ok(())
    }
    
    /// Real memory range mapping with 4-level page tables
    fn map_memory_range(
        &self,
        pml4_virt: VirtAddr,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        permissions: PagePermissions,
    ) -> Result<(), &'static str> {
        let page_size = 4096;
        let num_pages = (size + page_size - 1) / page_size;
        
        for i in 0..num_pages {
            let virt_addr = VirtAddr::new(virt_start.as_u64() + (i * page_size) as u64);
            let phys_addr = PhysAddr::new(phys_start.as_u64() + (i * page_size) as u64);
            
            self.map_single_page(pml4_virt, virt_addr, phys_addr, permissions)?;
        }
        
        Ok(())
    }
    
    /// Map single 4KB page with real page table manipulation
    fn map_single_page(
        &self,
        pml4_virt: VirtAddr,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        permissions: PagePermissions,
    ) -> Result<(), &'static str> {
        // Extract page table indices from virtual address
        let pml4_index = (virt_addr.as_u64() >> 39) & 0x1FF;
        let pdpt_index = (virt_addr.as_u64() >> 30) & 0x1FF;
        let pd_index = (virt_addr.as_u64() >> 21) & 0x1FF;
        let pt_index = (virt_addr.as_u64() >> 12) & 0x1FF;
        
        unsafe {
            // Get PML4 entry
            let pml4_table = pml4_virt.as_ptr::<u64>();
            let pml4_entry = pml4_table.add(pml4_index as usize);
            
            // Ensure PDPT exists
            let pdpt_phys = if (*pml4_entry & 1) == 0 {
                // Allocate new PDPT
                let pdpt_frame = self.allocate_page_table_frame()?;
                let pdpt_virt = self.frame_to_virt(pdpt_frame);
                core::ptr::write_bytes(pdpt_virt.as_mut_ptr::<u64>(), 0, 512);
                
                *pml4_entry = pdpt_frame.as_u64() | 0x3; // Present + Writable
                pdpt_frame
            } else {
                PhysAddr::new(*pml4_entry & 0x000FFFFFFFFFF000)
            };
            
            // Get PDPT entry
            let pdpt_virt = self.frame_to_virt(pdpt_phys);
            let pdpt_table = pdpt_virt.as_ptr::<u64>();
            let pdpt_entry = pdpt_table.add(pdpt_index as usize);
            
            // Ensure PD exists
            let pd_phys = if (*pdpt_entry & 1) == 0 {
                let pd_frame = self.allocate_page_table_frame()?;
                let pd_virt = self.frame_to_virt(pd_frame);
                core::ptr::write_bytes(pd_virt.as_mut_ptr::<u64>(), 0, 512);
                
                *pdpt_entry = pd_frame.as_u64() | 0x3;
                pd_frame
            } else {
                PhysAddr::new(*pdpt_entry & 0x000FFFFFFFFFF000)
            };
            
            // Get PD entry
            let pd_virt = self.frame_to_virt(pd_phys);
            let pd_table = pd_virt.as_ptr::<u64>();
            let pd_entry = pd_table.add(pd_index as usize);
            
            // Ensure PT exists
            let pt_phys = if (*pd_entry & 1) == 0 {
                let pt_frame = self.allocate_page_table_frame()?;
                let pt_virt = self.frame_to_virt(pt_frame);
                core::ptr::write_bytes(pt_virt.as_mut_ptr::<u64>(), 0, 512);
                
                *pd_entry = pt_frame.as_u64() | 0x3;
                pt_frame
            } else {
                PhysAddr::new(*pd_entry & 0x000FFFFFFFFFF000)
            };
            
            // Set final page table entry
            let pt_virt = self.frame_to_virt(pt_phys);
            let pt_table = pt_virt.as_ptr::<u64>();
            let pt_entry = pt_table.add(pt_index as usize);
            
            let mut entry_flags = 1u64; // Present
            if permissions.writable { entry_flags |= 2; }           // Writable
            if permissions.user_accessible { entry_flags |= 4; }   // User
            if !permissions.executable { entry_flags |= 1 << 63; } // NX
            if permissions.cache_disabled { entry_flags |= 16; }   // PCD
            
            *pt_entry = phys_addr.as_u64() | entry_flags;
        }
        
        // Cache page table entry
        let mut cache = self.page_tables.write();
        cache.insert(virt_addr.as_u64(), PageTableEntry {
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
        });
        
        Ok(())
    }
    
    /// Load page table into CR3 register
    fn load_page_table(&self, pml4_frame: PhysAddr) -> Result<(), &'static str> {
        unsafe {
            asm!("mov cr3, {}", in(reg) pml4_frame.as_u64());
        }
        
        *self.current_cr3.lock() = pml4_frame.as_u64();
        
        // Invalidate TLB
        self.invalidate_tlb_all();
        
        crate::log::logger::log_info!("Loaded new page table at 0x{:x}", pml4_frame.as_u64());
        Ok(())
    }
    
    /// Real TLB invalidation
    pub fn invalidate_tlb_all(&self) {
        unsafe {
            // Flush entire TLB by reloading CR3
            let cr3: u64;
            asm!("mov {}, cr3", out(reg) cr3);
            asm!("mov cr3, {}", in(reg) cr3);
        }
    }
    
    /// Invalidate specific TLB entry
    pub fn invalidate_tlb_page(&self, virt_addr: VirtAddr) {
        unsafe {
            asm!("invlpg [{}]", in(reg) virt_addr.as_u64());
        }
        
        // Add to invalidation queue for other CPUs
        let mut queue = self.tlb_invalidation_queue.lock();
        queue.push(virt_addr);
    }
    
    /// Allocate frame for page table
    fn allocate_page_table_frame(&self) -> Result<PhysAddr, &'static str> {
        // Use frame allocator to get physical page
        crate::memory::frame_alloc::allocate_frame()
            .ok_or("Failed to allocate page table frame")
    }
    
    /// Convert physical frame to virtual address for manipulation
    fn frame_to_virt(&self, frame: PhysAddr) -> VirtAddr {
        // Direct mapping in higher half
        VirtAddr::new(0xFFFF800000000000 + frame.as_u64())
    }
    
    /// Real memory protection change
    pub fn change_page_protection(
        &self,
        virt_addr: VirtAddr,
        new_permissions: PagePermissions,
    ) -> Result<(), &'static str> {
        // Walk page tables to find entry
        let current_cr3 = *self.current_cr3.lock();
        let pml4_virt = self.frame_to_virt(PhysAddr::new(current_cr3));
        
        // Update page table entry with new permissions
        self.update_page_entry(pml4_virt, virt_addr, new_permissions)?;
        
        // Invalidate TLB for this page
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
            // Walk to page table entry
            let pml4_table = pml4_virt.as_ptr::<u64>();
            let pml4_entry = *pml4_table.add(pml4_index as usize);
            if (pml4_entry & 1) == 0 { return Err("Page not mapped"); }
            
            let pdpt_virt = self.frame_to_virt(PhysAddr::new(pml4_entry & 0x000FFFFFFFFFF000));
            let pdpt_table = pdpt_virt.as_ptr::<u64>();
            let pdpt_entry = *pdpt_table.add(pdpt_index as usize);
            if (pdpt_entry & 1) == 0 { return Err("Page not mapped"); }
            
            let pd_virt = self.frame_to_virt(PhysAddr::new(pdpt_entry & 0x000FFFFFFFFFF000));
            let pd_table = pd_virt.as_ptr::<u64>();
            let pd_entry = *pd_table.add(pd_index as usize);
            if (pd_entry & 1) == 0 { return Err("Page not mapped"); }
            
            let pt_virt = self.frame_to_virt(PhysAddr::new(pd_entry & 0x000FFFFFFFFFF000));
            let pt_table = pt_virt.as_ptr::<u64>();
            let pt_entry_ptr = pt_table.add(pt_index as usize);
            let old_entry = *pt_entry_ptr;
            
            if (old_entry & 1) == 0 { return Err("Page not mapped"); }
            
            // Update permissions while preserving physical address
            let phys_addr = old_entry & 0x000FFFFFFFFFF000;
            let mut new_entry = phys_addr | 1; // Present
            
            if permissions.writable { new_entry |= 2; }
            if permissions.user_accessible { new_entry |= 4; }
            if !permissions.executable { new_entry |= 1 << 63; }
            if permissions.cache_disabled { new_entry |= 16; }
            
            *pt_entry_ptr = new_entry;
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PagePermissions {
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
    pub cache_disabled: bool,
}

// Global MMU instance
use spin::Once;
static REAL_MMU: Once<RealMMU> = Once::new();

pub fn init_real_mmu() -> Result<(), &'static str> {
    let mmu = REAL_MMU.call_once(|| RealMMU::new());
    mmu.initialize()
}

pub fn get_real_mmu() -> &'static RealMMU {
    REAL_MMU.get().expect("Real MMU not initialized")
}