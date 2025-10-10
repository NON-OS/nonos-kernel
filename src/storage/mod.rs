//! Ultra-Advanced Storage Subsystem
//!
//! Production storage with NVMe, AHCI, encryption, and high-performance I/O

pub mod ahci;
pub mod block_device;
pub mod crypto_storage;
pub mod nvme;
pub mod raid;
pub mod swap;

use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
        const READ            = 1 << 0;
        const WRITE           = 1 << 1;
        const TRIM            = 1 << 2;  // SSD trim support
        const FLUSH           = 1 << 3;  // Cache flush support
        const SECURE_ERASE    = 1 << 4;  // Secure erase support
        const ENCRYPTION      = 1 << 5;  // Hardware encryption
        const COMPRESSION     = 1 << 6;  // Hardware compression
        const DEDUPLICATION   = 1 << 7;  // Hardware deduplication
        const NCQ             = 1 << 8;  // Native Command Queuing
        const POWER_MANAGEMENT = 1 << 9;  // Power management
        const SMART           = 1 << 10; // S.M.A.R.T. monitoring
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

/// I/O request with advanced features
pub struct IoRequest {
    pub operation: IoOperation,
    pub lba: u64,           // Logical Block Address
    pub block_count: u32,   // Number of blocks
    pub buffer: VirtAddr,   // Data buffer
    pub buffer_size: usize, // Buffer size in bytes
    pub priority: u8,       // Request priority (0-255)
    pub flags: IoFlags,     // Request flags
    pub completion_callback: Option<Box<dyn Fn(IoResult) + Send + Sync>>,
    pub request_id: u64, // Unique request identifier
    pub timestamp: u64,  // Request timestamp
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
    /// Get device information
    fn device_info(&self) -> DeviceInfo;

    /// Get device capabilities
    fn capabilities(&self) -> DeviceCapabilities;

    /// Submit I/O request
    fn submit_request(&self, request: IoRequest) -> Result<(), IoStatus>;

    /// Check if device is ready
    fn is_ready(&self) -> bool;

    /// Get device statistics
    fn statistics(&self) -> &DeviceStatistics;

    /// Read blocks from the device
    fn read_blocks(
        &self,
        start_block: u64,
        block_count: u32,
        buffer: &mut [u8],
    ) -> Result<(), IoStatus>;

    /// Get total number of sectors
    fn total_sectors(&self) -> u64;

    /// Perform device maintenance
    fn maintenance(&self) -> Result<(), &'static str>;

    /// Get S.M.A.R.T. data
    fn smart_data(&self) -> Option<SmartData>;

    /// Secure erase device
    fn secure_erase(&self) -> Result<(), &'static str>;

    /// Set power state
    fn set_power_state(&self, state: PowerState) -> Result<(), &'static str>;

    /// Check if device supports secure erase
    fn supports_secure_erase(&self) -> bool;

    /// Verify sanitize completion
    fn verify_sanitize_completion(&self) -> Result<(), &'static str>;

    /// Wait for command completion
    fn wait_for_completion(&self, command_id: u16, timeout_ms: u64) -> Result<(), &'static str>;

    /// Parse controller identify data
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

        crate::log::logger::log_info!(
            "{}",
            &format!(
                "Registered storage device ID {} ({:?})",
                device_id,
                devices.last().unwrap().device_info().device_type
            )
        );

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

/// I/O scheduler with advanced algorithms
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

    /// Schedule I/O request using intelligent algorithms
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

    /// Process queued I/O requests with elevator algorithm
    fn process_queued_requests(&mut self) -> Result<(), IoStatus> {
        // Process high priority first
        while let Some((device, request)) = self.high_priority_queue.pop() {
            if self.active_requests >= self.max_concurrent_requests {
                // Put it back and break
                self.high_priority_queue.push((device, request));
                break;
            }

            self.submit_to_device(device, request)?;
        }

        // Process normal priority
        while let Some((device, request)) = self.normal_priority_queue.pop() {
            if self.active_requests >= self.max_concurrent_requests {
                self.normal_priority_queue.push((device, request));
                break;
            }

            self.submit_to_device(device, request)?;
        }

        // Process low priority
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
        self.active_requests += 1;
        device.submit_request(request)?;
        Ok(())
    }
}

/// Global storage manager instance
static STORAGE_MANAGER: StorageManager = StorageManager::new();

/// Initialize storage subsystem
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing advanced storage subsystem");

    // Initialize NVMe subsystem
    nvme::init()?;

    // Initialize AHCI subsystem
    ahci::init()?;

    // Initialize crypto storage
    crypto_storage::init()?;

    // Discover and register storage devices
    discover_storage_devices()?;

    crate::log::logger::log_info!("Storage subsystem initialized successfully");
    Ok(())
}

/// Discover and register all storage devices
fn discover_storage_devices() -> Result<(), &'static str> {
    // Scan PCI bus for NVMe controllers
    nvme::scan_and_register_nvme_devices(&STORAGE_MANAGER)?;

    // Scan PCI bus for AHCI controllers
    ahci::scan_and_register_ahci_devices(&STORAGE_MANAGER)?;

    Ok(())
}

/// Get global storage manager
pub fn get_storage_manager() -> &'static StorageManager {
    &STORAGE_MANAGER
}

/// Get primary storage device
pub fn get_primary_storage() -> Option<Box<dyn crate::storage::StorageDevice>> {
    let manager = &STORAGE_MANAGER;
    // Note: This would need to clone the device, but since StorageDevice
    // likely doesn't implement Clone, we'll return None for now
    // TODO: Implement a different approach for device access
    None
}

/// Submit I/O request to storage subsystem
pub fn submit_io_request(device_id: u32, request: IoRequest) -> Result<(), IoStatus> {
    STORAGE_MANAGER.submit_io(device_id, request)
}

/// Get storage subsystem statistics
pub fn get_stats() -> StorageStats {
    STORAGE_MANAGER.get_storage_stats()
}

use crate::storage::swap::{free_swap_slot, read_page, SwapSlot};
use x86_64::VirtAddr;

/// Read a page from swap storage
pub fn read_swap_page(swap_offset: u64) -> Result<Vec<u8>, &'static str> {
    // Create swap slot from offset
    let swap_slot = SwapSlot {
        device_id: (swap_offset >> 32) as u32, // High 32 bits are device ID
        slot: swap_offset & 0xFFFFFFFF,        // Low 32 bits are slot number
    };

    let mut buffer = [0u8; 4096];
    read_page(swap_slot, &mut buffer).map_err(|_| "Failed to read swap page")?;

    Ok(buffer.to_vec())
}

/// Free a page in swap storage  
pub fn free_swap_page(swap_offset: u64) {
    let swap_slot =
        SwapSlot { device_id: (swap_offset >> 32) as u32, slot: swap_offset & 0xFFFFFFFF };

    free_swap_slot(swap_slot);
}
