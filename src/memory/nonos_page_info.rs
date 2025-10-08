//! Page Information and Management
//!
//! Complete page tracking and metadata system

use x86_64::{VirtAddr, PhysAddr};
use alloc::collections::BTreeMap;
use spin::RwLock;

// Page flags for advanced memory management
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        const PRESENT       = 1 << 0;   // Page is present in memory
        const WRITABLE      = 1 << 1;   // Page is writable
        const USER          = 1 << 2;   // Page is accessible from userspace
        const ACCESSED      = 1 << 3;   // Page has been accessed
        const DIRTY         = 1 << 4;   // Page has been written to
        const HUGE_PAGE     = 1 << 5;   // This is a huge page (2MB/1GB)
        const GLOBAL        = 1 << 6;   // Page is global (not flushed on context switch)
        const NO_EXECUTE    = 1 << 7;   // Page is not executable
        const NO_CACHE      = 1 << 8;   // Page is not cached
        const WRITE_THROUGH = 1 << 9;   // Write-through caching
        
        // Extended flags for NONOS
        const COPY_ON_WRITE = 1 << 16;  // Copy-on-write page
        const SWAP_PAGE     = 1 << 17;  // Page is swapped out
        const LOCKED        = 1 << 18;  // Page is locked in memory
        const ENCRYPTED     = 1 << 19;  // Page is encrypted
        const COMPRESSED    = 1 << 20;  // Page is compressed
        const ZERO_FILL     = 1 << 21;  // Page should be zero-filled on access
        const DEMAND_PAGING = 1 << 22;  // Page uses demand paging
        const SHARED        = 1 << 23;  // Page is shared between processes
        const EXECUTABLE    = 1 << 24;  // Page contains executable code
        const READONLY      = 1 << 25;  // Page is read-only
        const DEVICE_MEMORY = 1 << 26;  // Page maps device memory
        const RESERVED      = 1 << 27;  // Page is reserved
        const GUARD_PAGE    = 1 << 28;  // Page is a guard page
        const STACK_PAGE    = 1 << 29;  // Page is part of a stack
        const HEAP_PAGE     = 1 << 30;  // Page is part of a heap
        const CODE_PAGE     = 1 << 31;  // Page contains code
    }
}

/// Page information structure
#[derive(Debug, Clone)]
pub struct PageInfo {
    pub virtual_addr: VirtAddr,
    pub physical_addr: Option<PhysAddr>,
    pub flags: PageFlags,
    pub reference_count: u32,
    pub last_accessed: u64,
    pub owner_process: Option<u32>,
    pub swap_location: Option<SwapInfo>,
    pub encryption_key: Option<[u8; 32]>,
    pub compression_ratio: Option<f32>,
}

/// Swap information for swapped-out pages
#[derive(Debug, Clone, Copy)]
pub struct SwapInfo {
    pub swap_device_id: u32,
    pub swap_slot: u64,
    pub compressed_size: u32,
    pub checksum: u32,
}

impl Default for PageInfo {
    fn default() -> Self {
        PageInfo {
            virtual_addr: VirtAddr::new(0),
            physical_addr: None,
            flags: PageFlags::empty(),
            reference_count: 0,
            last_accessed: 0,
            owner_process: None,
            swap_location: None,
            encryption_key: None,
            compression_ratio: None,
        }
    }
}

impl PageInfo {
    /// Create new page info
    pub fn new(virtual_addr: VirtAddr, physical_addr: Option<PhysAddr>, flags: PageFlags) -> Self {
        PageInfo {
            virtual_addr,
            physical_addr,
            flags,
            reference_count: 1,
            last_accessed: crate::time::now_ns(),
            owner_process: None,
            swap_location: None,
            encryption_key: None,
            compression_ratio: None,
        }
    }
    
    /// Check if page is present in physical memory
    pub fn is_present(&self) -> bool {
        self.flags.contains(PageFlags::PRESENT) && self.physical_addr.is_some()
    }
    
    /// Check if page is swapped out
    pub fn is_swapped(&self) -> bool {
        self.flags.contains(PageFlags::SWAP_PAGE) && self.swap_location.is_some()
    }
    
    /// Check if page is copy-on-write
    pub fn is_cow(&self) -> bool {
        self.flags.contains(PageFlags::COPY_ON_WRITE)
    }
    
    /// Check if page is writable
    pub fn is_writable(&self) -> bool {
        self.flags.contains(PageFlags::WRITABLE) && !self.flags.contains(PageFlags::READONLY)
    }
    
    /// Check if page is executable
    pub fn is_executable(&self) -> bool {
        self.flags.contains(PageFlags::EXECUTABLE) && !self.flags.contains(PageFlags::NO_EXECUTE)
    }
    
    /// Mark page as accessed
    pub fn mark_accessed(&mut self) {
        self.flags.insert(PageFlags::ACCESSED);
        self.last_accessed = crate::time::now_ns();
    }
    
    /// Mark page as dirty
    pub fn mark_dirty(&mut self) {
        if self.is_writable() {
            self.flags.insert(PageFlags::DIRTY);
        }
    }
    
    /// Increment reference count
    pub fn add_reference(&mut self) {
        self.reference_count += 1;
    }
    
    /// Decrement reference count
    pub fn remove_reference(&mut self) -> u32 {
        if self.reference_count > 0 {
            self.reference_count -= 1;
        }
        self.reference_count
    }
    
    /// Set swap location
    pub fn set_swap_location(&mut self, swap_info: SwapInfo) {
        self.swap_location = Some(swap_info);
        self.flags.insert(PageFlags::SWAP_PAGE);
        self.flags.remove(PageFlags::PRESENT);
        self.physical_addr = None;
    }
    
    /// Clear swap location
    pub fn clear_swap_location(&mut self) {
        self.swap_location = None;
        self.flags.remove(PageFlags::SWAP_PAGE);
    }
    
    /// Set encryption key
    pub fn set_encryption_key(&mut self, key: [u8; 32]) {
        self.encryption_key = Some(key);
        self.flags.insert(PageFlags::ENCRYPTED);
    }
    
    /// Clear encryption
    pub fn clear_encryption(&mut self) {
        self.encryption_key = None;
        self.flags.remove(PageFlags::ENCRYPTED);
    }
}

/// Global page information table
static PAGE_INFO_TABLE: RwLock<BTreeMap<u64, PageInfo>> = RwLock::new(BTreeMap::new());

/// Get page information for a virtual address
pub fn get_page_info(addr: VirtAddr) -> Option<PageInfo> {
    let page_addr = addr.as_u64() & !0xFFF; // Page-align address
    let table = PAGE_INFO_TABLE.read();
    table.get(&page_addr).cloned()
}

/// Set page information for a virtual address
pub fn set_page_info(addr: VirtAddr, info: PageInfo) {
    let page_addr = addr.as_u64() & !0xFFF; // Page-align address
    let mut table = PAGE_INFO_TABLE.write();
    table.insert(page_addr, info);
}

/// Remove page information for a virtual address
pub fn remove_page_info(addr: VirtAddr) -> Option<PageInfo> {
    let page_addr = addr.as_u64() & !0xFFF; // Page-align address
    let mut table = PAGE_INFO_TABLE.write();
    table.remove(&page_addr)
}

/// Update page information
pub fn update_page_info<F>(addr: VirtAddr, updater: F) -> bool
where
    F: FnOnce(&mut PageInfo),
{
    let page_addr = addr.as_u64() & !0xFFF; // Page-align address
    let mut table = PAGE_INFO_TABLE.write();
    
    if let Some(page_info) = table.get_mut(&page_addr) {
        updater(page_info);
        true
    } else {
        false
    }
}

/// Get all page information (for debugging/monitoring)
pub fn get_all_page_info() -> alloc::vec::Vec<(VirtAddr, PageInfo)> {
    let table = PAGE_INFO_TABLE.read();
    table.iter()
        .map(|(&addr, info)| (VirtAddr::new(addr), info.clone()))
        .collect()
}

/// Statistics for page management
#[derive(Debug, Default)]
pub struct PageStats {
    pub total_pages: u64,
    pub present_pages: u64,
    pub swapped_pages: u64,
    pub cow_pages: u64,
    pub locked_pages: u64,
    pub encrypted_pages: u64,
    pub compressed_pages: u64,
    pub shared_pages: u64,
    pub executable_pages: u64,
    pub writable_pages: u64,
    pub user_pages: u64,
    pub kernel_pages: u64,
}

/// Get comprehensive page statistics
pub fn get_page_stats() -> PageStats {
    let mut stats = PageStats::default();
    let table = PAGE_INFO_TABLE.read();
    
    for (_, page_info) in table.iter() {
        stats.total_pages += 1;
        
        if page_info.is_present() {
            stats.present_pages += 1;
        }
        
        if page_info.is_swapped() {
            stats.swapped_pages += 1;
        }
        
        if page_info.is_cow() {
            stats.cow_pages += 1;
        }
        
        if page_info.flags.contains(PageFlags::LOCKED) {
            stats.locked_pages += 1;
        }
        
        if page_info.flags.contains(PageFlags::ENCRYPTED) {
            stats.encrypted_pages += 1;
        }
        
        if page_info.flags.contains(PageFlags::COMPRESSED) {
            stats.compressed_pages += 1;
        }
        
        if page_info.flags.contains(PageFlags::SHARED) {
            stats.shared_pages += 1;
        }
        
        if page_info.is_executable() {
            stats.executable_pages += 1;
        }
        
        if page_info.is_writable() {
            stats.writable_pages += 1;
        }
        
        if page_info.flags.contains(PageFlags::USER) {
            stats.user_pages += 1;
        } else {
            stats.kernel_pages += 1;
        }
    }
    
    stats
}

/// Initialize page information tracking
pub fn init() {
    crate::log::logger::log_info!("Page information tracking initialized");
}

/// Cleanup page information (remove unreferenced pages)
pub fn cleanup_unreferenced_pages() -> u64 {
    let mut table = PAGE_INFO_TABLE.write();
    let mut removed_count = 0u64;
    
    table.retain(|_addr, page_info| {
        if page_info.reference_count == 0 && !page_info.flags.contains(PageFlags::LOCKED) {
            removed_count += 1;
            false // Remove this entry
        } else {
            true // Keep this entry
        }
    });
    
    removed_count
}