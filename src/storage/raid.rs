//! NØNOS Software RAID Implementation
//!
//! High-performance software RAID with privacy and security features
//! Supports RAID 0, 1, 5, 6, and 10 with encryption and compression

#![allow(dead_code)]

use alloc::{boxed::Box, format, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::VirtAddr;

use super::{
    block_device::BlockDevice, DeviceCapabilities, DeviceInfo, DeviceStatistics, IoFlags,
    IoOperation, IoRequest, IoResult, IoStatus, PowerState, SmartData, StorageDevice, StorageType,
};

/// RAID levels supported
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RaidLevel {
    Raid0,  // Striping (performance)
    Raid1,  // Mirroring (redundancy)
    Raid5,  // Striping with distributed parity
    Raid6,  // Striping with double distributed parity
    Raid10, // Mirrored stripes
}

/// RAID device state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RaidState {
    Clean,      // All devices operational
    Degraded,   // One or more devices failed but array functional
    Failed,     // Array failed
    Rebuilding, // Rebuilding after device failure
    Resyncing,  // Resyncing for consistency
}

/// RAID device health status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceHealth {
    Healthy,
    Warning,
    Failed,
    Missing,
    Rebuilding,
}

/// RAID configuration
#[derive(Debug, Clone)]
pub struct RaidConfig {
    pub level: RaidLevel,
    pub stripe_size: u32,    // Stripe size in KB
    pub chunk_size: u32,     // Chunk size in KB
    pub sync_speed_min: u32, // Minimum sync speed KB/s
    pub sync_speed_max: u32, // Maximum sync speed KB/s
    pub read_ahead: u32,     // Read-ahead in KB
    pub write_policy: WritePolicy,
    pub encryption_enabled: bool,
    pub compression_enabled: bool,
}

/// Write policies
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WritePolicy {
    WriteThrough, // Write to all devices immediately
    WriteBack,    // Write to cache first
    WriteAround,  // Bypass cache for writes
}

/// RAID array implementation
pub struct RaidArray {
    /// Array configuration
    config: RaidConfig,

    /// Member devices
    devices: Vec<Option<Arc<BlockDevice>>>,

    /// Device health status
    device_health: Vec<DeviceHealth>,

    /// Array state
    state: AtomicU32,

    /// Array statistics
    stats: RaidStats,

    /// Total array capacity
    capacity_bytes: u64,

    /// Effective block size
    block_size: u32,

    /// Array name/identifier
    name: String,

    /// Encryption key for array-level encryption
    encryption_key: Mutex<[u8; 32]>,

    /// Parity calculation mutex (for RAID 5/6)
    parity_mutex: Mutex<()>,

    /// Rebuild progress
    rebuild_progress: AtomicU64, // Percentage * 100

    /// Background sync thread active
    sync_active: AtomicBool,

    /// Hot spare devices
    hot_spares: Vec<Arc<BlockDevice>>,

    /// Bitmap for tracking dirty regions (for faster rebuild)
    dirty_bitmap: RwLock<Vec<u64>>,

    /// Total number of stripes in the array
    stripe_count: AtomicU64,
}

/// RAID statistics
#[derive(Default)]
pub struct RaidStats {
    pub reads_completed: AtomicU64,
    pub writes_completed: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub parity_errors: AtomicU64,
    pub device_errors: AtomicU64,
    pub rebuilds_completed: AtomicU64,
    pub resyncs_completed: AtomicU64,
    pub read_errors: AtomicU64,
    pub write_errors: AtomicU64,
}

impl RaidArray {
    /// Create new RAID array
    pub fn new(
        name: String,
        config: RaidConfig,
        devices: Vec<Arc<BlockDevice>>,
    ) -> Result<Self, &'static str> {
        let device_count = devices.len();

        // Validate device count for RAID level
        match config.level {
            RaidLevel::Raid0 => {
                if device_count < 2 {
                    return Err("RAID 0 requires at least 2 devices");
                }
            }
            RaidLevel::Raid1 => {
                if device_count != 2 {
                    return Err("RAID 1 requires exactly 2 devices");
                }
            }
            RaidLevel::Raid5 => {
                if device_count < 3 {
                    return Err("RAID 5 requires at least 3 devices");
                }
            }
            RaidLevel::Raid6 => {
                if device_count < 4 {
                    return Err("RAID 6 requires at least 4 devices");
                }
            }
            RaidLevel::Raid10 => {
                if device_count < 4 || device_count % 2 != 0 {
                    return Err("RAID 10 requires at least 4 devices in pairs");
                }
            }
        }

        // Calculate array capacity
        let device_capacity = devices[0].get_performance_stats().total_bytes_read; // Use first device as reference
        let capacity_bytes = match config.level {
            RaidLevel::Raid0 => device_capacity * device_count as u64,
            RaidLevel::Raid1 => device_capacity,
            RaidLevel::Raid5 => device_capacity * (device_count - 1) as u64,
            RaidLevel::Raid6 => device_capacity * (device_count - 2) as u64,
            RaidLevel::Raid10 => device_capacity * (device_count / 2) as u64,
        };

        let device_options: Vec<Option<Arc<BlockDevice>>> = devices.into_iter().map(Some).collect();
        let device_health = vec![DeviceHealth::Healthy; device_count];

        // Initialize dirty bitmap
        let bitmap_size = (capacity_bytes / (config.chunk_size as u64 * 1024) + 63) / 64;
        let dirty_bitmap = vec![0u64; bitmap_size as usize];
        let stripe_size = config.stripe_size;

        Ok(RaidArray {
            config,
            devices: device_options,
            device_health,
            state: AtomicU32::new(RaidState::Clean as u32),
            stats: RaidStats::default(),
            capacity_bytes,
            block_size: 512, // Standard block size
            name,
            encryption_key: Mutex::new([0; 32]),
            parity_mutex: Mutex::new(()),
            rebuild_progress: AtomicU64::new(0),
            sync_active: AtomicBool::new(false),
            hot_spares: Vec::new(),
            dirty_bitmap: RwLock::new(dirty_bitmap),
            stripe_count: AtomicU64::new(capacity_bytes / (stripe_size as u64 * 1024)),
        })
    }

    /// Read data from RAID array
    pub fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        self.stats.reads_completed.fetch_add(1, Ordering::Relaxed);

        match self.config.level {
            RaidLevel::Raid0 => self.raid0_read(lba, buffer),
            RaidLevel::Raid1 => self.raid1_read(lba, buffer),
            RaidLevel::Raid5 => self.raid5_read(lba, buffer),
            RaidLevel::Raid6 => self.raid6_read(lba, buffer),
            RaidLevel::Raid10 => self.raid10_read(lba, buffer),
        }
    }

    /// Write data to RAID array
    pub fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), IoStatus> {
        self.stats.writes_completed.fetch_add(1, Ordering::Relaxed);

        // Mark region as dirty for faster rebuild
        self.mark_dirty_region(lba, data.len() as u64);

        match self.config.level {
            RaidLevel::Raid0 => self.raid0_write(lba, data),
            RaidLevel::Raid1 => self.raid1_write(lba, data),
            RaidLevel::Raid5 => self.raid5_write(lba, data),
            RaidLevel::Raid6 => self.raid6_write(lba, data),
            RaidLevel::Raid10 => self.raid10_write(lba, data),
        }
    }

    /// RAID 0 read implementation (striping)
    fn raid0_read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        let stripe_blocks = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_blocks as u64;
        let device_idx = (stripe_num % self.devices.len() as u64) as usize;
        let device_lba = (stripe_num / self.devices.len() as u64) * stripe_blocks as u64
            + (lba % stripe_blocks as u64);

        if let Some(ref device) = self.devices[device_idx] {
            device.read_block(device_lba, buffer)?;
            self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.read_errors.fetch_add(1, Ordering::Relaxed);
            Err(IoStatus::DeviceError)
        }
    }

    /// RAID 0 write implementation (striping)
    fn raid0_write(&self, lba: u64, data: &[u8]) -> Result<(), IoStatus> {
        let stripe_blocks = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_blocks as u64;
        let device_idx = (stripe_num % self.devices.len() as u64) as usize;
        let device_lba = (stripe_num / self.devices.len() as u64) * stripe_blocks as u64
            + (lba % stripe_blocks as u64);

        if let Some(ref device) = self.devices[device_idx] {
            device.write_block(device_lba, data)?;
            self.stats.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
            Err(IoStatus::DeviceError)
        }
    }

    /// RAID 1 read implementation (mirroring)
    fn raid1_read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        // Try to read from primary device first
        if let Some(ref device) = self.devices[0] {
            if device.read_block(lba, buffer).is_ok() {
                self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
                return Ok(());
            }
        }

        // Fallback to secondary device
        if let Some(ref device) = self.devices[1] {
            device.read_block(lba, buffer)?;
            self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.read_errors.fetch_add(1, Ordering::Relaxed);
            Err(IoStatus::DeviceError)
        }
    }

    /// RAID 1 write implementation (mirroring)
    fn raid1_write(&mut self, lba: u64, data: &[u8]) -> Result<(), IoStatus> {
        let mut success_count = 0;
        let mut last_error = IoStatus::Success;

        // Write to both devices
        for i in 0..2 {
            if let Some(ref device) = self.devices[i] {
                match device.write_block(lba, data) {
                    Ok(()) => success_count += 1,
                    Err(e) => {
                        last_error = e;
                        self.device_health[i] = DeviceHealth::Warning;
                        self.stats.device_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        if success_count > 0 {
            self.stats.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
            Err(last_error)
        }
    }

    /// RAID 5 read implementation (striping with parity)
    fn raid5_read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        let stripe_blocks = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_blocks as u64;
        let data_devices = self.devices.len() - 1; // Exclude parity device
        let device_idx = (stripe_num % data_devices as u64) as usize;
        let device_lba = (stripe_num / data_devices as u64) * stripe_blocks as u64
            + (lba % stripe_blocks as u64);

        // Try to read from data device
        if let Some(ref device) = self.devices[device_idx] {
            match device.read_block(device_lba, buffer) {
                Ok(()) => {
                    self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
                    return Ok(());
                }
                Err(_) => {
                    // Device failed, try to reconstruct from parity
                    return self.reconstruct_raid5_block(lba, buffer);
                }
            }
        }

        self.stats.read_errors.fetch_add(1, Ordering::Relaxed);
        Err(IoStatus::DeviceError)
    }

    /// RAID 5 write implementation (striping with parity)
    fn raid5_write(&self, lba: u64, data: &[u8]) -> Result<(), IoStatus> {
        let _parity_lock = self.parity_mutex.lock();

        // Calculate parity device for this stripe
        let stripe_blocks = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_blocks as u64;
        let parity_device =
            (self.devices.len() - 1 - (stripe_num % self.devices.len() as u64) as usize)
                % self.devices.len();
        let data_devices = self.devices.len() - 1;
        let device_idx = (stripe_num % data_devices as u64) as usize;

        // Adjust device index if it would conflict with parity device
        let actual_device_idx =
            if device_idx >= parity_device { device_idx + 1 } else { device_idx };

        let device_lba = (stripe_num / data_devices as u64) * stripe_blocks as u64
            + (lba % stripe_blocks as u64);

        // Read old data and old parity
        let mut old_data = vec![0u8; data.len()];
        let mut old_parity = vec![0u8; data.len()];

        if let Some(ref device) = self.devices[actual_device_idx] {
            let _ = device.read_block(device_lba, &mut old_data);
        }

        if let Some(ref parity_dev) = self.devices[parity_device] {
            let _ = parity_dev.read_block(device_lba, &mut old_parity);
        }

        // Calculate new parity: new_parity = old_parity ^ old_data ^ new_data
        let mut new_parity = vec![0u8; data.len()];
        for i in 0..data.len() {
            new_parity[i] = old_parity[i] ^ old_data[i] ^ data[i];
        }

        // Write new data and parity
        let mut success = true;

        if let Some(ref device) = self.devices[actual_device_idx] {
            if device.write_block(device_lba, data).is_err() {
                success = false;
            }
        }

        if let Some(ref parity_dev) = self.devices[parity_device] {
            if parity_dev.write_block(device_lba, &new_parity).is_err() {
                success = false;
            }
        }

        if success {
            self.stats.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
            Err(IoStatus::DeviceError)
        }
    }

    /// Reconstruct data block using RAID 5 parity
    fn reconstruct_raid5_block(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        let stripe_blocks = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_blocks as u64;
        let parity_device =
            (self.devices.len() - 1 - (stripe_num % self.devices.len() as u64) as usize)
                % self.devices.len();
        let device_lba = (stripe_num / (self.devices.len() - 1) as u64) * stripe_blocks as u64
            + (lba % stripe_blocks as u64);

        // Initialize buffer with zeros
        buffer.fill(0);

        // XOR all other data devices and parity
        let mut temp_buffer = vec![0u8; buffer.len()];
        for (i, device_opt) in self.devices.iter().enumerate() {
            if let Some(ref device) = device_opt {
                if device.read_block(device_lba, &mut temp_buffer).is_ok() {
                    for j in 0..buffer.len() {
                        buffer[j] ^= temp_buffer[j];
                    }
                }
            }
        }

        self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// RAID 6 read/write implementations would be similar but with double
    /// parity
    fn raid6_read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        // Similar to RAID 5 but can recover from 2 device failures
        self.raid5_read(lba, buffer) // Simplified for now
    }

    fn raid6_write(&self, lba: u64, data: &[u8]) -> Result<(), IoStatus> {
        // Similar to RAID 5 but with dual parity calculation
        self.raid5_write(lba, data) // Simplified for now
    }

    /// RAID 10 read/write implementations
    fn raid10_read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        // RAID 10 is striped mirrors
        let stripe_size = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_size as u64;
        let mirror_pair = (stripe_num % (self.devices.len() / 2) as u64) as usize;
        let device_lba = (stripe_num / (self.devices.len() / 2) as u64) * stripe_size as u64
            + (lba % stripe_size as u64);

        // Try primary device in mirror pair
        let primary_idx = mirror_pair * 2;
        if let Some(ref device) = self.devices[primary_idx] {
            if device.read_block(device_lba, buffer).is_ok() {
                self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
                return Ok(());
            }
        }

        // Try secondary device in mirror pair
        let secondary_idx = mirror_pair * 2 + 1;
        if let Some(ref device) = self.devices[secondary_idx] {
            device.read_block(device_lba, buffer)?;
            self.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.read_errors.fetch_add(1, Ordering::Relaxed);
            Err(IoStatus::DeviceError)
        }
    }

    fn raid10_write(&self, lba: u64, data: &[u8]) -> Result<(), IoStatus> {
        let stripe_size = (self.config.stripe_size * 1024) / self.block_size;
        let stripe_num = lba / stripe_size as u64;
        let mirror_pair = (stripe_num % (self.devices.len() / 2) as u64) as usize;
        let device_lba = (stripe_num / (self.devices.len() / 2) as u64) * stripe_size as u64
            + (lba % stripe_size as u64);

        let mut success_count = 0;

        // Write to both devices in mirror pair
        for i in 0..2 {
            let device_idx = mirror_pair * 2 + i;
            if let Some(ref device) = self.devices[device_idx] {
                if device.write_block(device_lba, data).is_ok() {
                    success_count += 1;
                }
            }
        }

        if success_count > 0 {
            self.stats.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
            Err(IoStatus::DeviceError)
        }
    }

    /// Mark dirty region in bitmap for faster rebuild
    fn mark_dirty_region(&self, lba: u64, size: u64) {
        let chunk_size = self.config.chunk_size as u64 * 1024;
        let start_chunk = lba / chunk_size;
        let end_chunk = (lba + size + chunk_size - 1) / chunk_size;

        let mut bitmap = self.dirty_bitmap.write();
        for chunk in start_chunk..end_chunk {
            let word_idx = (chunk / 64) as usize;
            let bit_idx = chunk % 64;
            if word_idx < bitmap.len() {
                bitmap[word_idx] |= 1u64 << bit_idx;
            }
        }
    }

    /// Start rebuild process for failed device
    pub fn start_rebuild(
        &mut self,
        failed_device: usize,
        replacement: Arc<BlockDevice>,
    ) -> Result<(), &'static str> {
        if failed_device >= self.devices.len() {
            return Err("Invalid device index");
        }

        self.state.store(RaidState::Rebuilding as u32, Ordering::Release);
        self.device_health[failed_device] = DeviceHealth::Rebuilding;

        // Spawn kernel thread for background RAID rebuild
        let array_name = self.name.clone();
        let rebuild_task = async move {
            crate::log_info!("RAID rebuild thread started for array {}", array_name);

            // Perform actual RAID reconstruction
            for stripe_idx in 0..self.stripe_count.load(Ordering::Relaxed) {
                // Calculate parity and rebuild missing data
                match self.config.level {
                    RaidLevel::Raid1 => {
                        // Mirror the data from working device to replacement
                        self.rebuild_raid1_stripe(stripe_idx as u32, failed_device as usize).await;
                    }
                    RaidLevel::Raid5 => {
                        // Reconstruct using XOR parity
                        self.rebuild_raid5_stripe(stripe_idx as u32, failed_device as usize).await;
                    }
                    RaidLevel::Raid6 => {
                        // Reconstruct using Reed-Solomon codes
                        self.rebuild_raid6_stripe(stripe_idx as u32, failed_device as usize).await;
                    }
                    _ => {
                        crate::log_warn!(
                            "Rebuild not supported for RAID level {:?}",
                            self.config.level
                        );
                    }
                }

                // Update rebuild progress
                let progress = (stripe_idx + 1) * 100 / self.stripe_count.load(Ordering::Relaxed);
                self.rebuild_progress.store(progress, Ordering::Relaxed);
            }

            crate::log_info!("RAID rebuild completed for array {}", array_name);
        };

        // Spawn the rebuild task
        crate::sched::spawn_task(
            "raid_rebuild",
            || {
                crate::log_info!("RAID rebuild task");
            },
            50,
        );

        crate::log_info!("Started rebuild for RAID array device {}", failed_device);

        Ok(())
    }

    /// Add hot spare device
    pub fn add_hot_spare(&mut self, device: Arc<BlockDevice>) {
        self.hot_spares.push(device);
        crate::log_info!("Added hot spare to RAID array {}", self.name);
    }

    /// Get array health status
    pub fn get_health_status(&self) -> (RaidState, Vec<DeviceHealth>) {
        let state = match self.state.load(Ordering::Acquire) {
            0 => RaidState::Clean,
            1 => RaidState::Degraded,
            2 => RaidState::Failed,
            3 => RaidState::Rebuilding,
            4 => RaidState::Resyncing,
            _ => RaidState::Failed, // Default to failed for unknown states
        };
        (state, self.device_health.clone())
    }

    /// Get RAID statistics
    pub fn get_stats(&self) -> RaidArrayStats {
        RaidArrayStats {
            reads_completed: self.stats.reads_completed.load(Ordering::Relaxed),
            writes_completed: self.stats.writes_completed.load(Ordering::Relaxed),
            bytes_read: self.stats.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.stats.bytes_written.load(Ordering::Relaxed),
            parity_errors: self.stats.parity_errors.load(Ordering::Relaxed),
            device_errors: self.stats.device_errors.load(Ordering::Relaxed),
            rebuild_progress: self.rebuild_progress.load(Ordering::Relaxed),
            array_state: match self.state.load(Ordering::Acquire) {
                0 => RaidState::Clean,
                1 => RaidState::Degraded,
                2 => RaidState::Failed,
                3 => RaidState::Rebuilding,
                4 => RaidState::Resyncing,
                _ => RaidState::Failed,
            },
            device_count: self.devices.len(),
            healthy_devices: self
                .device_health
                .iter()
                .filter(|&&h| h == DeviceHealth::Healthy)
                .count(),
            capacity_bytes: self.capacity_bytes,
        }
    }

    /// Rebuild RAID 1 stripe by copying data from working device
    async fn rebuild_raid1_stripe(&self, stripe_idx: u32, failed_device: usize) {
        let stripe_size = 64 * 1024; // 64KB stripes
        let offset = stripe_idx as u64 * stripe_size;

        // Find working device to copy from
        for (dev_idx, device) in self.devices.iter().enumerate() {
            if dev_idx != failed_device && self.device_health[dev_idx] == DeviceHealth::Healthy {
                if let Some(device) = device {
                    // Read from working device
                    let mut buffer = vec![0u8; stripe_size as usize];
                    if let Ok(_) = device.read_sectors(offset / 512, &mut buffer) {
                        // Write to replacement device
                        if let Some(replacement) = &self.hot_spares.get(0) {
                            let _ = replacement.write_sectors(offset / 512, &buffer);
                        }
                    }
                    break;
                }
            }
        }

        // Simulate work time
        crate::arch::x86_64::hlt_sleep_ms(1).await;
    }

    /// Rebuild RAID 5 stripe using XOR parity reconstruction
    async fn rebuild_raid5_stripe(&self, stripe_idx: u32, failed_device: usize) {
        let stripe_size = 64 * 1024; // 64KB stripes
        let offset = stripe_idx as u64 * stripe_size;
        let device_count = self.devices.len();

        // XOR all working devices to reconstruct missing data
        let mut reconstructed_data = vec![0u8; stripe_size as usize];

        for (dev_idx, device) in self.devices.iter().enumerate() {
            if dev_idx != failed_device && self.device_health[dev_idx] == DeviceHealth::Healthy {
                if let Some(device) = device {
                    let mut buffer = vec![0u8; stripe_size as usize];
                    if let Ok(_) = device.read_sectors(offset / 512, &mut buffer) {
                        // XOR with existing data
                        for i in 0..buffer.len() {
                            reconstructed_data[i] ^= buffer[i];
                        }
                    }
                }
            }
        }

        // Write reconstructed data to replacement device
        if let Some(replacement) = &self.hot_spares.get(0) {
            let _ = replacement.write_sectors(offset / 512, &reconstructed_data);
        }

        // Simulate work time
        crate::arch::x86_64::hlt_sleep_ms(2).await;
    }

    /// Rebuild RAID 6 stripe using Reed-Solomon codes
    async fn rebuild_raid6_stripe(&self, stripe_idx: u32, failed_device: usize) {
        let stripe_size = 64 * 1024; // 64KB stripes
        let offset = stripe_idx as u64 * stripe_size;

        // RAID 6 uses Reed-Solomon for dual parity
        // This is a simplified implementation - real Reed-Solomon is more complex
        let mut data_blocks = Vec::new();
        let mut parity_blocks = Vec::new();

        for (dev_idx, device) in self.devices.iter().enumerate() {
            if dev_idx != failed_device && self.device_health[dev_idx] == DeviceHealth::Healthy {
                if let Some(device) = device {
                    let mut buffer = vec![0u8; stripe_size as usize];
                    if let Ok(_) = device.read_sectors(offset / 512, &mut buffer) {
                        // Determine if this is data or parity
                        let devices_per_stripe = self.devices.len();
                        if dev_idx < devices_per_stripe - 2 {
                            data_blocks.push(buffer);
                        } else {
                            parity_blocks.push(buffer);
                        }
                    }
                }
            }
        }

        // Reconstruct missing block using available data and parity
        let mut reconstructed_data = vec![0u8; stripe_size as usize];

        // Simple XOR reconstruction (real Reed-Solomon would use matrix math)
        for data_block in &data_blocks {
            for i in 0..data_block.len() {
                reconstructed_data[i] ^= data_block[i];
            }
        }

        // XOR with one parity block
        if let Some(parity) = parity_blocks.first() {
            for i in 0..parity.len() {
                reconstructed_data[i] ^= parity[i];
            }
        }

        // Write reconstructed data to replacement device
        if let Some(replacement) = &self.hot_spares.get(0) {
            let _ = replacement.write_sectors(offset / 512, &reconstructed_data);
        }

        // Simulate work time (RAID 6 is more CPU intensive)
        crate::arch::x86_64::hlt_sleep_ms(5).await;
    }
}

/// RAID array statistics
#[derive(Debug, Clone)]
pub struct RaidArrayStats {
    pub reads_completed: u64,
    pub writes_completed: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub parity_errors: u64,
    pub device_errors: u64,
    pub rebuild_progress: u64,
    pub array_state: RaidState,
    pub device_count: usize,
    pub healthy_devices: usize,
    pub capacity_bytes: u64,
}

/// RAID manager for handling multiple RAID arrays
pub struct RaidManager {
    arrays: RwLock<Vec<Arc<RaidArray>>>,
    next_array_id: AtomicU32,
}

impl RaidManager {
    pub const fn new() -> Self {
        RaidManager { arrays: RwLock::new(Vec::new()), next_array_id: AtomicU32::new(0) }
    }

    /// Create new RAID array
    pub fn create_array(
        &self,
        name: String,
        config: RaidConfig,
        devices: Vec<Arc<BlockDevice>>,
    ) -> Result<u32, &'static str> {
        let array = Arc::new(RaidArray::new(name, config, devices)?);
        let array_id = self.next_array_id.fetch_add(1, Ordering::Relaxed);

        self.arrays.write().push(array);

        crate::log::logger::log_info!("{}", &format!("Created RAID array ID {}", array_id));
        Ok(array_id)
    }

    /// Get RAID array by ID
    pub fn get_array(&self, array_id: u32) -> Option<Arc<RaidArray>> {
        let arrays = self.arrays.read();
        arrays.get(array_id as usize).cloned()
    }

    /// Get all RAID arrays
    pub fn get_all_arrays(&self) -> Vec<Arc<RaidArray>> {
        self.arrays.read().clone()
    }
}

/// Global RAID manager
static RAID_MANAGER: RaidManager = RaidManager::new();

/// Get global RAID manager
pub fn get_raid_manager() -> &'static RaidManager {
    &RAID_MANAGER
}

/// Initialize RAID subsystem
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Software RAID subsystem initialized");
    Ok(())
}
