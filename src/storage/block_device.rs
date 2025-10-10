//! NØNOS Block Device Layer
//!
//! High-performance block device abstraction with caching, encryption, and
//! compression

#![allow(dead_code)]

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::VirtAddr;

use super::{IoFlags, IoOperation, IoRequest, IoStatus, StorageDevice};

/// Block cache entry
#[derive(Clone)]
pub struct CacheEntry {
    pub block_num: u64,
    pub data: Vec<u8>,
    pub dirty: bool,
    pub access_count: u64,
    pub last_access: u64,
    pub encrypted: bool,
    pub compressed: bool,
}

/// Block cache statistics
#[derive(Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub write_backs: AtomicU64,
    pub compression_saves: AtomicU64,
    pub encryption_ops: AtomicU64,
}

/// Block device wrapper with advanced caching
pub struct BlockDevice {
    /// Underlying storage device
    storage_device: Arc<dyn StorageDevice>,

    /// Block cache (LRU with write-back)
    cache: RwLock<BTreeMap<u64, CacheEntry>>,

    /// Cache configuration
    max_cache_entries: usize,
    block_size: u32,

    /// Cache statistics
    cache_stats: CacheStats,

    /// Write-back queue for dirty blocks
    write_back_queue: Mutex<Vec<u64>>,

    /// Compression enabled
    compression_enabled: AtomicU32,

    /// Encryption enabled
    encryption_enabled: AtomicU32,

    /// Encryption key
    encryption_key: Mutex<[u8; 32]>,

    /// Device ID for tracking
    device_id: u32,

    /// Performance counters
    read_ops: AtomicU64,
    write_ops: AtomicU64,
    total_bytes_read: AtomicU64,
    total_bytes_written: AtomicU64,
}

impl BlockDevice {
    /// Create new block device wrapper
    pub fn new(
        storage_device: Arc<dyn StorageDevice>,
        device_id: u32,
        max_cache_mb: usize,
    ) -> Self {
        let device_info = storage_device.device_info();
        let max_cache_entries = (max_cache_mb * 1024 * 1024) / device_info.block_size as usize;

        BlockDevice {
            storage_device,
            cache: RwLock::new(BTreeMap::new()),
            max_cache_entries,
            block_size: device_info.block_size,
            cache_stats: CacheStats::default(),
            write_back_queue: Mutex::new(Vec::new()),
            compression_enabled: AtomicU32::new(0),
            encryption_enabled: AtomicU32::new(0),
            encryption_key: Mutex::new([0; 32]),
            device_id,
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            total_bytes_read: AtomicU64::new(0),
            total_bytes_written: AtomicU64::new(0),
        }
    }

    /// Read block with caching
    pub fn read_block(&self, block_num: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        self.read_ops.fetch_add(1, Ordering::Relaxed);

        // Check cache first
        {
            let mut cache = self.cache.write();
            if let Some(entry) = cache.get_mut(&block_num) {
                // Cache hit
                entry.access_count += 1;
                entry.last_access = crate::time::current_ticks();

                buffer.copy_from_slice(&entry.data);
                self.cache_stats.hits.fetch_add(1, Ordering::Relaxed);
                self.total_bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);

                return Ok(());
            }
        }

        // Cache miss - read from storage
        self.cache_stats.misses.fetch_add(1, Ordering::Relaxed);

        let lba = block_num;
        let block_count = (buffer.len() as u32 + self.block_size - 1) / self.block_size;

        let request = IoRequest {
            operation: IoOperation::Read,
            lba,
            block_count,
            buffer: VirtAddr::new(buffer.as_ptr() as u64),
            buffer_size: buffer.len(),
            priority: 128,
            flags: IoFlags::empty(),
            completion_callback: None,
            request_id: self.generate_request_id(),
            timestamp: crate::time::current_ticks(),
        };

        self.storage_device.submit_request(request)?;

        // Add to cache if enabled
        if self.max_cache_entries > 0 {
            self.add_to_cache(block_num, buffer.to_vec(), false);
        }

        self.total_bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Write block with caching
    pub fn write_block(&self, block_num: u64, data: &[u8]) -> Result<(), IoStatus> {
        self.write_ops.fetch_add(1, Ordering::Relaxed);

        let write_through = true; // For now, always write through

        if write_through {
            // Write-through: write to storage immediately
            let lba = block_num;
            let block_count = (data.len() as u32 + self.block_size - 1) / self.block_size;

            let request = IoRequest {
                operation: IoOperation::Write,
                lba,
                block_count,
                buffer: VirtAddr::new(data.as_ptr() as u64),
                buffer_size: data.len(),
                priority: 128,
                flags: IoFlags::SYNC,
                completion_callback: None,
                request_id: self.generate_request_id(),
                timestamp: crate::time::current_ticks(),
            };

            self.storage_device.submit_request(request)?;
        }

        // Update cache
        self.add_to_cache(block_num, data.to_vec(), !write_through);

        self.total_bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Add entry to cache with LRU eviction
    fn add_to_cache(&self, block_num: u64, data: Vec<u8>, dirty: bool) {
        let mut cache = self.cache.write();

        // Check if cache is full
        while cache.len() >= self.max_cache_entries {
            self.evict_lru_entry(&mut cache);
        }

        let current_time = crate::time::current_ticks();
        let encrypted = self.encryption_enabled.load(Ordering::Relaxed) != 0;
        let compressed = self.compression_enabled.load(Ordering::Relaxed) != 0;

        let mut final_data = data;

        // Apply compression if enabled
        if compressed {
            final_data = self.compress_data(&final_data);
            self.cache_stats.compression_saves.fetch_add(1, Ordering::Relaxed);
        }

        // Apply encryption if enabled
        if encrypted {
            final_data = self.encrypt_data(&final_data);
            self.cache_stats.encryption_ops.fetch_add(1, Ordering::Relaxed);
        }

        let entry = CacheEntry {
            block_num,
            data: final_data,
            dirty,
            access_count: 1,
            last_access: current_time,
            encrypted,
            compressed,
        };

        cache.insert(block_num, entry);

        if dirty {
            let mut queue = self.write_back_queue.lock();
            queue.push(block_num);
        }
    }

    /// Evict least recently used entry
    fn evict_lru_entry(&self, cache: &mut BTreeMap<u64, CacheEntry>) {
        let mut lru_block = None;
        let mut lru_time = u64::MAX;

        for (block_num, entry) in cache.iter() {
            if entry.last_access < lru_time {
                lru_time = entry.last_access;
                lru_block = Some(*block_num);
            }
        }

        if let Some(block_num) = lru_block {
            if let Some(entry) = cache.remove(&block_num) {
                if entry.dirty {
                    // Write back dirty entry
                    self.write_back_entry(&entry);
                }
                self.cache_stats.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Write back dirty cache entry to storage
    fn write_back_entry(&self, entry: &CacheEntry) {
        let mut data = entry.data.clone();

        // Decrypt if encrypted
        if entry.encrypted {
            data = self.decrypt_data(&data);
        }

        // Decompress if compressed
        if entry.compressed {
            data = self.decompress_data(&data);
        }

        let request = IoRequest {
            operation: IoOperation::Write,
            lba: entry.block_num,
            block_count: (data.len() as u32 + self.block_size - 1) / self.block_size,
            buffer: VirtAddr::new(data.as_ptr() as u64),
            buffer_size: data.len(),
            priority: 64, // Lower priority for write-back
            flags: IoFlags::ASYNC,
            completion_callback: None,
            request_id: self.generate_request_id(),
            timestamp: crate::time::current_ticks(),
        };

        if self.storage_device.submit_request(request).is_ok() {
            self.cache_stats.write_backs.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Compress data using simple algorithm
    fn compress_data(&self, data: &[u8]) -> Vec<u8> {
        // Simple RLE compression for demonstration
        let mut compressed = Vec::new();
        if data.is_empty() {
            return compressed;
        }

        let mut current_byte = data[0];
        let mut count = 1u8;

        for &byte in &data[1..] {
            if byte == current_byte && count < 255 {
                count += 1;
            } else {
                compressed.push(count);
                compressed.push(current_byte);
                current_byte = byte;
                count = 1;
            }
        }

        compressed.push(count);
        compressed.push(current_byte);

        // Return original if compression doesn't help
        if compressed.len() >= data.len() {
            data.to_vec()
        } else {
            compressed
        }
    }

    /// Decompress data
    fn decompress_data(&self, data: &[u8]) -> Vec<u8> {
        let mut decompressed = Vec::new();

        for chunk in data.chunks_exact(2) {
            let count = chunk[0];
            let byte = chunk[1];

            for _ in 0..count {
                decompressed.push(byte);
            }
        }

        decompressed
    }

    /// Encrypt data using XOR cipher (simple demonstration)
    fn encrypt_data(&self, data: &[u8]) -> Vec<u8> {
        let key = self.encryption_key.lock();
        let mut encrypted = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            encrypted.push(byte ^ key[i % 32]);
        }

        encrypted
    }

    /// Decrypt data using XOR cipher
    fn decrypt_data(&self, data: &[u8]) -> Vec<u8> {
        // XOR encryption is its own inverse
        self.encrypt_data(data)
    }

    /// Flush all dirty cache entries
    pub fn flush_cache(&self) -> Result<(), IoStatus> {
        let cache = self.cache.read();
        let dirty_entries: Vec<_> = cache.values().filter(|e| e.dirty).cloned().collect();
        drop(cache);

        for entry in dirty_entries {
            self.write_back_entry(&entry);
        }

        // Clear write-back queue
        self.write_back_queue.lock().clear();

        Ok(())
    }

    /// Enable compression
    pub fn enable_compression(&self) {
        self.compression_enabled.store(1, Ordering::Release);
        crate::log_info!("Compression enabled for block device {}", self.device_id);
    }

    /// Enable encryption with key
    pub fn enable_encryption(&self, key: &[u8; 32]) {
        *self.encryption_key.lock() = *key;
        self.encryption_enabled.store(1, Ordering::Release);
        crate::log_info!("Encryption enabled for block device {}", self.device_id);
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> BlockCacheStats {
        BlockCacheStats {
            hits: self.cache_stats.hits.load(Ordering::Relaxed),
            misses: self.cache_stats.misses.load(Ordering::Relaxed),
            hit_ratio: {
                let hits = self.cache_stats.hits.load(Ordering::Relaxed);
                let misses = self.cache_stats.misses.load(Ordering::Relaxed);
                let total = hits + misses;
                if total > 0 {
                    (hits * 100) / total
                } else {
                    0
                }
            },
            evictions: self.cache_stats.evictions.load(Ordering::Relaxed),
            write_backs: self.cache_stats.write_backs.load(Ordering::Relaxed),
            cache_entries: self.cache.read().len(),
            compression_saves: self.cache_stats.compression_saves.load(Ordering::Relaxed),
            encryption_ops: self.cache_stats.encryption_ops.load(Ordering::Relaxed),
        }
    }

    /// Get device performance stats
    pub fn get_performance_stats(&self) -> BlockDeviceStats {
        BlockDeviceStats {
            read_ops: self.read_ops.load(Ordering::Relaxed),
            write_ops: self.write_ops.load(Ordering::Relaxed),
            total_bytes_read: self.total_bytes_read.load(Ordering::Relaxed),
            total_bytes_written: self.total_bytes_written.load(Ordering::Relaxed),
            cache_stats: self.get_cache_stats(),
        }
    }

    /// Generate unique request ID
    fn generate_request_id(&self) -> u64 {
        static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Trim/discard blocks (for SSDs)
    pub fn trim_blocks(&self, start_block: u64, block_count: u32) -> Result<(), IoStatus> {
        let request = IoRequest {
            operation: IoOperation::Trim,
            lba: start_block,
            block_count,
            buffer: VirtAddr::new(0),
            buffer_size: 0,
            priority: 64,
            flags: IoFlags::ASYNC,
            completion_callback: None,
            request_id: self.generate_request_id(),
            timestamp: crate::time::current_ticks(),
        };

        self.storage_device.submit_request(request)
    }

    /// Read multiple blocks efficiently
    pub fn read_blocks(&self, start_block: u64, blocks: &mut [Vec<u8>]) -> Result<(), IoStatus> {
        for (i, block_buffer) in blocks.iter_mut().enumerate() {
            self.read_block(start_block + i as u64, block_buffer)?;
        }
        Ok(())
    }

    /// Write multiple blocks efficiently  
    pub fn write_blocks(&self, start_block: u64, blocks: &[Vec<u8>]) -> Result<(), IoStatus> {
        for (i, block_data) in blocks.iter().enumerate() {
            self.write_block(start_block + i as u64, block_data)?;
        }
        Ok(())
    }

    /// Read sectors (512-byte units)
    pub fn read_sectors(&self, sector: u64, buffer: &mut [u8]) -> Result<(), IoStatus> {
        let bytes_per_sector = 512;
        let start_block = (sector * bytes_per_sector) / self.block_size as u64;
        let sector_count = (buffer.len() as u64 + bytes_per_sector - 1) / bytes_per_sector;

        // For simplicity, read block by block
        for i in 0..sector_count {
            let block_num = start_block + i;
            let sector_offset = i * bytes_per_sector;
            let bytes_to_read =
                core::cmp::min(bytes_per_sector, buffer.len() as u64 - sector_offset);

            if sector_offset + bytes_to_read <= buffer.len() as u64 {
                let mut block_buffer = vec![0u8; self.block_size as usize];
                self.read_block(block_num, &mut block_buffer)?;

                let src_offset = ((sector * bytes_per_sector) % self.block_size as u64) as usize;
                let dst_start = sector_offset as usize;
                let dst_end = dst_start + bytes_to_read as usize;

                if dst_end <= buffer.len() && src_offset < block_buffer.len() {
                    let copy_len =
                        core::cmp::min(bytes_to_read as usize, block_buffer.len() - src_offset);
                    buffer[dst_start..dst_start + copy_len]
                        .copy_from_slice(&block_buffer[src_offset..src_offset + copy_len]);
                }
            }
        }

        Ok(())
    }

    /// Write sectors (512-byte units)  
    pub fn write_sectors(&self, sector: u64, buffer: &[u8]) -> Result<(), IoStatus> {
        let bytes_per_sector = 512;
        let start_block = (sector * bytes_per_sector) / self.block_size as u64;
        let sector_count = (buffer.len() as u64 + bytes_per_sector - 1) / bytes_per_sector;

        // For simplicity, write block by block
        for i in 0..sector_count {
            let block_num = start_block + i;
            let sector_offset = i * bytes_per_sector;
            let bytes_to_write =
                core::cmp::min(bytes_per_sector, buffer.len() as u64 - sector_offset);

            if sector_offset + bytes_to_write <= buffer.len() as u64 {
                // For partial block writes, read-modify-write
                let mut block_buffer = vec![0u8; self.block_size as usize];
                let _ = self.read_block(block_num, &mut block_buffer); // Ignore errors for new blocks

                let dst_offset = ((sector * bytes_per_sector) % self.block_size as u64) as usize;
                let src_start = sector_offset as usize;
                let src_end = src_start + bytes_to_write as usize;

                if src_end <= buffer.len() && dst_offset < block_buffer.len() {
                    let copy_len =
                        core::cmp::min(bytes_to_write as usize, block_buffer.len() - dst_offset);
                    block_buffer[dst_offset..dst_offset + copy_len]
                        .copy_from_slice(&buffer[src_start..src_start + copy_len]);
                }

                self.write_block(block_num, &block_buffer)?;
            }
        }

        Ok(())
    }
}

/// Block cache statistics
#[derive(Debug, Clone)]
pub struct BlockCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: u64,
    pub evictions: u64,
    pub write_backs: u64,
    pub cache_entries: usize,
    pub compression_saves: u64,
    pub encryption_ops: u64,
}

/// Block device performance statistics
#[derive(Debug, Clone)]
pub struct BlockDeviceStats {
    pub read_ops: u64,
    pub write_ops: u64,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub cache_stats: BlockCacheStats,
}

/// Block device manager for managing multiple block devices
pub struct BlockDeviceManager {
    devices: RwLock<Vec<Arc<BlockDevice>>>,
    next_device_id: AtomicU32,
}

impl BlockDeviceManager {
    pub const fn new() -> Self {
        BlockDeviceManager { devices: RwLock::new(Vec::new()), next_device_id: AtomicU32::new(0) }
    }

    /// Register a new block device
    pub fn register_device(&self, storage_device: Arc<dyn StorageDevice>, cache_mb: usize) -> u32 {
        let device_id = self.next_device_id.fetch_add(1, Ordering::Relaxed);
        let block_device = Arc::new(BlockDevice::new(storage_device, device_id, cache_mb));

        self.devices.write().push(block_device);

        crate::log_info!("Registered block device {} with {}MB cache", device_id, cache_mb);

        device_id
    }

    /// Get block device by ID
    pub fn get_device(&self, device_id: u32) -> Option<Arc<BlockDevice>> {
        let devices = self.devices.read();
        devices.iter().find(|d| d.device_id == device_id).cloned()
    }

    /// Get all block devices
    pub fn get_all_devices(&self) -> Vec<Arc<BlockDevice>> {
        self.devices.read().clone()
    }

    /// Flush all devices
    pub fn flush_all(&self) -> Result<(), IoStatus> {
        for device in self.devices.read().iter() {
            device.flush_cache()?;
        }
        Ok(())
    }
}

/// Global block device manager
static BLOCK_DEVICE_MANAGER: BlockDeviceManager = BlockDeviceManager::new();

/// Get global block device manager
pub fn get_block_device_manager() -> &'static BlockDeviceManager {
    &BLOCK_DEVICE_MANAGER
}

/// Initialize block device subsystem
pub fn init() -> Result<(), &'static str> {
    crate::log_info!("Block device layer initialized");
    Ok(())
}
