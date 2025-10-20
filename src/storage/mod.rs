//! Storage Subsystem

pub mod nonos_nvme;
pub mod nonos_ahci;
pub mod nonos_block_device;
pub mod nonos_raid;
pub mod nonos_crypto_storage;
// pub mod nonos_swap; // TODO: missing module

// Re-export for compatibility
pub use nonos_nvme as nvme;
pub use nonos_ahci as ahci;
pub use nonos_block_device as block_device;
pub use nonos_raid as raid;
pub use nonos_crypto_storage as crypto_storage;
// pub use nonos_swap as swap; // TODO: missing module

use alloc::{vec::Vec, boxed::Box, sync::Arc, format, string::String};
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use spin::{Mutex, RwLock};

/// Storage device types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StorageType {
    NVMe,
    SataSsd,
    SataHdd,
    UsbMassStorage,
    VirtualDisk,
    RamDisk,
}

/// Storage device capabilities
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct DeviceCapabilities: u32 {
        const READ             = 1 << 0;
        const WRITE            = 1 << 1;
        const TRIM             = 1 << 2;  // SSD trim support
        const FLUSH            = 1 << 3;  // Cache flush support
        const SECURE_ERASE     = 1 << 4;  // Secure erase support
        const ENCRYPTION       = 1 << 5;  // Hardware encryption
        const COMPRESSION      = 1 << 6;  // Hardware compression
        const DEDUPLICATION    = 1 << 7;  // Hardware deduplication
        const NCQ              = 1 << 8;  // Native Command Queuing
        const POWER_MANAGEMENT = 1 << 9;  // Power management
        const SMART            = 1 << 10; // S.M.A.R.T. monitoring
    }
}

/// I/O operation types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoOperation {
    Read,
    Write,
    Trim,
    Flush,
    SecureErase,
}

/// I/O request + features
pub struct IoRequest {
    pub operation: IoOperation,
    pub lba: u64,           // Logical Block Address
    pub block_count: u32,   // Number of blocks
    pub buffer: VirtAddr,   // Data buffer
    pub buffer_size: usize, // Buffer size in bytes
    pub priority: u8,       // Request priority (0-255)
    pub flags: IoFlags,     // Request flags
    pub completion_callback: Option<Box<dyn Fn(IoResult) + Send + Sync>>,
    pub request_id: u64,    // Unique request identifier
    pub timestamp: u64,     // Request timestamp
}

/// I/O request flags
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct IoFlags: u32 {
        const SYNC           = 1 << 0;  // Synchronous operation
        const ASYNC          = 1 << 1;  // Asynchronous operation
        const HIGH_PRIORITY  = 1 << 2;  // High priority request
        const BYPASS_CACHE   = 1 << 3;  // Bypass cache
        const WRITE_THROUGH  = 1 << 4;  // Write-through cache
        const ATOMIC         = 1 << 5;  // Atomic operation
        const ENCRYPTED      = 1 << 6;  // Encrypted I/O
        const COMPRESSED     = 1 << 7;  // Compressed I/O
    }
}

/// I/O operation result
#[derive(Debug, Clone, Copy)]
pub struct IoResult {
    pub status: IoStatus,
    pub bytes_transferred: usize,
    pub error_code: u32,
    pub completion_time: u64,
}

/// I/O status codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoStatus {
    Success,
    Pending,
    DeviceError,
    TimeoutError,
    InvalidRequest,
    DeviceNotReady,
    MediaError,
    CommunicationError,
    EncryptionError,
    CompressionError,
}

/// Storage device statistics
#[derive(Debug, Default)]
pub struct DeviceStatistics {
    pub reads_completed: AtomicU64,
    pub writes_completed: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub read_errors: AtomicU64,
    pub write_errors: AtomicU64,
    pub average_read_latency: AtomicU64,
    pub average_write_latency: AtomicU64,
    pub queue_depth: AtomicU32,
    pub temperature: AtomicU32,
    pub power_on_hours: AtomicU64,
    pub wear_level: AtomicU32,
    pub secure_erases_performed: AtomicU64,
    pub last_secure_erase_time: AtomicU64,
}

/// Storage device trait
pub trait StorageDevice: Send + Sync {
    fn device_info(&self) -> DeviceInfo;
    fn capabilities(&self) -> DeviceCapabilities;
    fn submit_request(&self, request: IoRequest) -> Result<(), IoStatus>;
    fn is_ready(&self) -> bool;
    fn statistics(&self) -> &DeviceStatistics;
    fn read_blocks(&self, start_block: u64, block_count: u32, buffer: &mut [u8]) -> Result<(), IoStatus>;
    fn total_sectors(&self) -> u64;
    fn maintenance(&self) -> Result<(), &'static str>;
    fn smart_data(&self) -> Option<SmartData>;
    fn secure_erase(&self) -> Result<(), &'static str>;
    fn set_power_state(&self, state: PowerState) -> Result<(), &'static str>;
    fn supports_secure_erase(&self) -> bool;
    fn verify_sanitize_completion(&self) -> Result<(), &'static str>;
    fn wait_for_completion(&self, command_id: u16, timeout_ms: u64) -> Result<(), &'static str>;
    fn parse_controller_identify(&self, data: &[u8]) -> Result<(), &'static str>;
}

/// Device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_type: StorageType,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub firmware_version: String,
    pub capacity_bytes: u64,
    pub block_size: u32,
    pub max_transfer_size: u32,
    pub max_queue_depth: u32,
    pub features: DeviceCapabilities,
}

/// Power management states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PowerState {
    Active,
    Idle,
    Standby,
    Sleep,
    PowerOff,
}

/// S.M.A.R.T. data structure
#[derive(Debug, Clone)]
pub struct SmartData {
    pub temperature: u32,
    pub power_on_hours: u64,
    pub power_cycles: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub error_log_entries: u64,
    pub critical_warning: u8,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u64,
    pub data_units_written: u64,
    pub host_read_commands: u64,
    pub host_write_commands: u64,
}

/// Storage manager
pub struct StorageManager {
    devices: RwLock<Vec<Arc<dyn StorageDevice>>>,
    io_scheduler: Mutex<IoScheduler>,
    device_id_counter: AtomicU32,
}

impl StorageManager {
    pub const fn new() -> Self {
        StorageManager {
            devices: RwLock::new(Vec::new()),
            io_scheduler: Mutex::new(IoScheduler::new()),
            device_id_counter: AtomicU32::new(0),
        }
    }

    /// Register a new storage device
    pub fn register_device(&self, device: Arc<dyn StorageDevice>) -> u32 {
        let device_id = self.device_id_counter.fetch_add(1, Ordering::Relaxed);
        let mut devices = self.devices.write();
        devices.push(device);

        crate::log::logger::log_info!("{}", &format!(
            "Registered storage device ID {} ({:?})",
            device_id,
            devices.last().unwrap().device_info().device_type
        ));

        device_id
    }

    /// Get device by ID
    pub fn get_device(&self, device_id: u32) -> Option<Arc<dyn StorageDevice>> {
        let devices = self.devices.read();
        devices.get(device_id as usize).cloned()
    }

    /// Submit I/O request to scheduler
    pub fn submit_io(&self, device_id: u32, request: IoRequest) -> Result<(), IoStatus> {
        if let Some(device) = self.get_device(device_id) {
            let mut scheduler = self.io_scheduler.lock();
            scheduler.schedule_request(device, request)
        } else {
            Err(IoStatus::InvalidRequest)
        }
    }

    /// Get storage statistics
    pub fn get_storage_stats(&self) -> StorageStats {
        let devices = self.devices.read();
        let mut stats = StorageStats::default();

        for device in devices.iter() {
            let device_stats = device.statistics();
            stats.total_reads += device_stats.reads_completed.load(Ordering::Relaxed);
            stats.total_writes += device_stats.writes_completed.load(Ordering::Relaxed);
            stats.total_bytes_read += device_stats.bytes_read.load(Ordering::Relaxed);
            stats.total_bytes_written += device_stats.bytes_written.load(Ordering::Relaxed);
        }

        stats
    }

    /// Perform maintenance on all devices
    pub fn maintenance_all_devices(&self) -> Result<(), &'static str> {
        let devices = self.devices.read();
        for device in devices.iter() {
            device.maintenance()?;
        }
        Ok(())
    }
}

/// Global storage statistics
#[derive(Debug, Default)]
pub struct StorageStats {
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub active_requests: u32,
    pub pending_requests: u32,
}

/// I/O scheduler with algorithms
pub struct IoScheduler {
    high_priority_queue: Vec<(Arc<dyn StorageDevice>, IoRequest)>,
    normal_priority_queue: Vec<(Arc<dyn StorageDevice>, IoRequest)>,
    low_priority_queue: Vec<(Arc<dyn StorageDevice>, IoRequest)>,
    active_requests: u32,
    max_concurrent_requests: u32,
}

impl IoScheduler {
    pub const fn new() -> Self {
        IoScheduler {
            high_priority_queue: Vec::new(),
            normal_priority_queue: Vec::new(),
            low_priority_queue: Vec::new(),
            active_requests: 0,
            max_concurrent_requests: 64,
        }
    }

    /// Schedule I/O request using algorithms
    pub fn schedule_request(
        &mut self,
        device: Arc<dyn StorageDevice>,
        request: IoRequest,
    ) -> Result<(), IoStatus> {
        if self.active_requests >= self.max_concurrent_requests {
            return Err(IoStatus::DeviceNotReady);
        }

        // Prioritize requests based on flags and priority
        if request.flags.contains(IoFlags::HIGH_PRIORITY) || request.priority > 200 {
            self.high_priority_queue.push((device, request));
        } else if request.priority > 100 {
            self.normal_priority_queue.push((device, request));
        } else {
            self.low_priority_queue.push((device, request));
        }

        // Process queued requests
        self.process_queued_requests()
    }

    /// Process queued I/O requests
    fn process_queued_requests(&mut self) -> Result<(), IoStatus> {
        // High priority first
        while let Some((device, request)) = self.high_priority_queue.pop() {
            if self.active_requests >= self.max_concurrent_requests {
                self.high_priority_queue.push((device, request));
                break;
            }
            self.submit_to_device(device, request)?;
        }
        // Normal priority
        while let Some((device, request)) = self.normal_priority_queue.pop() {
            if self.active_requests >= self.max_concurrent_requests {
                self.normal_priority_queue.push((device, request));
                break;
            }
            self.submit_to_device(device, request)?;
        }
        // Low priority
        while let Some((device, request)) = self.low_priority_queue.pop() {
            if self.active_requests >= self.max_concurrent_requests {
                self.low_priority_queue.push((device, request));
                break;
            }
            self.submit_to_device(device, request)?;
        }

        Ok(())
    }

    fn submit_to_device(
        &mut self,
        device: Arc<dyn StorageDevice>,
        request: IoRequest,
    ) -> Result<(), IoStatus> {
        self.active_requests = self.active_requests.saturating_add(1);
        let res = device.submit_request(request);
        // In RAM-only path, device submission is synchronous; decrement now.
        self.active_requests = self.active_requests.saturating_sub(1);
        res
    }
}

/// Global storage manager instance
static STORAGE_MANAGER: StorageManager = StorageManager::new();

/// Initialize storage subsystem
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing advanced storage subsystem");

    // Initialize subsystems
    nonos_nvme::init()?;
    nonos_ahci::init()?;
    nonos_crypto_storage::init()?;

    // Discover and register storage devices
    discover_storage_devices()?;

    crate::log::logger::log_info!("Storage subsystem initialized successfully");
    Ok(())
}

/// Discover and register all storage devices
fn discover_storage_devices() -> Result<(), &'static str> {
    // Scan for devices (NVMe shim will ensure a RAM disk fallback)
    nonos_nvme::scan_and_register_nvme_devices(&STORAGE_MANAGER)?;
    nonos_ahci::scan_and_register_ahci_devices(&STORAGE_MANAGER)?;

    // Ensure a default RAM disk exists even if scans didn’t add one.
    crate::storage::nonos_block_device::RamDisk::ensure_default_registered(&STORAGE_MANAGER);

    Ok(())
}

/// Get global storage manager
pub fn get_storage_manager() -> &'static StorageManager {
    &STORAGE_MANAGER
}

/// Get primary storage device (device 0)
pub fn get_primary_storage() -> Option<Arc<dyn crate::storage::StorageDevice>> {
    STORAGE_MANAGER.get_device(0)
}

/// Submit I/O request to storage subsystem
pub fn submit_io_request(device_id: u32, request: IoRequest) -> Result<(), IoStatus> {
    STORAGE_MANAGER.submit_io(device_id, request)
}

/// Get storage subsystem statistics
pub fn get_stats() -> StorageStats {
    STORAGE_MANAGER.get_storage_stats()
}

use x86_64::VirtAddr;

/// Swap slot identifier
#[derive(Debug, Clone, Copy)]
pub struct SwapSlot {
    device_id: u32,
    slot: u64,
}

impl SwapSlot {
    /// Create a new swap slot
    pub fn new(device_id: u32, slot: u64) -> Self {
        Self { device_id, slot }
    }
}

/// Swap manager for handling page swapping
static SWAP_MANAGER: Mutex<SwapManager> = Mutex::new(SwapManager::new());

struct SwapManager {
    swap_table: hashbrown::HashMap<u64, Vec<u8>>,
    next_slot: AtomicU64,
    total_size: AtomicU64,
}

impl SwapManager {
    const fn new() -> Self {
        Self {
            swap_table: hashbrown::HashMap::new(),
            next_slot: AtomicU64::new(1),
            total_size: AtomicU64::new(0),
        }
    }

    fn allocate_slot(&mut self) -> u64 {
        self.next_slot.fetch_add(1, Ordering::SeqCst)
    }

    fn write_page(&mut self, slot_id: u64, data: Vec<u8>) -> Result<(), &'static str> {
        if data.len() != 4096 {
            return Err("Invalid page size");
        }
        
        self.swap_table.insert(slot_id, data);
        self.total_size.fetch_add(4096, Ordering::SeqCst);
        Ok(())
    }

    fn read_page(&mut self, slot_id: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        if buffer.len() < 4096 {
            return Err("Buffer too small");
        }

        match self.swap_table.get(&slot_id) {
            Some(data) => {
                buffer[..4096].copy_from_slice(data);
                Ok(())
            }
            None => Err("Swap slot not found")
        }
    }

    fn free_slot(&mut self, slot_id: u64) -> Result<(), &'static str> {
        match self.swap_table.remove(&slot_id) {
            Some(_) => {
                self.total_size.fetch_sub(4096, Ordering::SeqCst);
                Ok(())
            }
            None => Err("Swap slot not found")
        }
    }
}

/// Read a page from swap slot
fn read_page(swap_slot: SwapSlot, buffer: &mut [u8]) -> Result<(), &'static str> {
    let slot_id = (swap_slot.device_id as u64) << 32 | swap_slot.slot;
    SWAP_MANAGER.lock().read_page(slot_id, buffer)
}

/// Free a swap slot
fn free_swap_slot(swap_slot: SwapSlot) {
    let slot_id = (swap_slot.device_id as u64) << 32 | swap_slot.slot;
    let _ = SWAP_MANAGER.lock().free_slot(slot_id);
}

/// Allocate a new swap slot and write data
pub fn allocate_swap_page(data: &[u8]) -> Result<u64, &'static str> {
    if data.len() != 4096 {
        return Err("Invalid page size");
    }
    
    let mut manager = SWAP_MANAGER.lock();
    let slot_id = manager.allocate_slot();
    manager.write_page(slot_id, data.to_vec())?;
    Ok(slot_id)
}

/// Read a page from swap storage
pub fn read_swap_page(swap_offset: u64) -> Result<Vec<u8>, &'static str> {
    // Create swap slot from offset
    let swap_slot = SwapSlot {
        device_id: (swap_offset >> 32) as u32,  // High 32 bits are device ID
        slot: swap_offset & 0xFFFFFFFF,         // Low 32 bits are slot number
    };

    let mut buffer = [0u8; 4096];
    read_page(swap_slot, &mut buffer)
        .map_err(|_| "Failed to read swap page")?;

    Ok(buffer.to_vec())
}

/// Free a page in swap storage
pub fn free_swap_page(swap_offset: u64) {
    let swap_slot = SwapSlot {
        device_id: (swap_offset >> 32) as u32,
        slot: swap_offset & 0xFFFFFFFF,
    };

    free_swap_slot(swap_slot);
}
