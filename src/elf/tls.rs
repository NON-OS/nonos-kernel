//! Thread Local Storage (TLS) Support for ELF Loader

use x86_64::VirtAddr;

/// TLS information for a loaded ELF image.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// Address of the TLS template in memory.
    pub template_addr: VirtAddr,
    /// Size of the TLS template in bytes.
    pub template_size: usize,
    /// Total memory size needed for TLS area.
    pub memory_size: usize,
    /// Required alignment for TLS area.
    pub alignment: usize,
}

impl TlsInfo {
    /// Create a new TLS info struct.
    pub fn new(template_addr: VirtAddr, template_size: usize, memory_size: usize, alignment: usize) -> Self {
        Self {
            template_addr,
            template_size,
            memory_size,
            alignment,
        }
    }
}