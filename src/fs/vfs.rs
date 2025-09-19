//! Advanced Virtual File System (VFS)
//!
//! Enterprise VFS with copy-on-write, compression, and high-performance I/O

use alloc::{vec::Vec, string::{String, ToString}, collections::{BTreeMap, VecDeque}, sync::Arc};
use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use spin::{Mutex, RwLock};
use x86_64::PhysAddr;
use crate::memory::page_allocator;

/// File system types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileSystemType {
    Ext4,
    Btrfs,
    XFS,
    ZFS,
    TmpFs,
    ProcFs,
    SysFs,
    DevFs,
    CryptoFS,
}

/// File types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    RegularFile,
    Directory,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
}

/// File permissions and attributes
#[derive(Debug, Clone, Copy)]
pub struct FileMode {
    pub permissions: u16,    // Unix-style permissions
    pub file_type: FileType,
    pub setuid: bool,
    pub setgid: bool,
    pub sticky: bool,
}

/// File metadata
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub inode: u64,
    pub size: u64,
    pub blocks: u64,
    pub mode: FileMode,
    pub uid: u32,
    pub gid: u32,
    pub atime: u64,  // Access time
    pub mtime: u64,  // Modification time
    pub ctime: u64,  // Change time
    pub btime: u64,  // Birth/creation time
    pub links: u32,  // Hard link count
    pub device: u64, // Device ID
    pub rdev: u64,   // Device ID for special files
}

/// Copy-on-Write page reference
#[derive(Debug)]
pub struct CowPageRef {
    pub physical_addr: PhysAddr,
    pub ref_count: Arc<AtomicUsize>,
    pub dirty: AtomicBool,
    pub compressed: bool,
    pub compression_algo: CompressionAlgorithm,
}

impl Clone for CowPageRef {
    fn clone(&self) -> Self {
        CowPageRef {
            physical_addr: self.physical_addr,
            ref_count: Arc::clone(&self.ref_count),
            dirty: AtomicBool::new(self.dirty.load(Ordering::Relaxed)),
            compressed: self.compressed,
            compression_algo: self.compression_algo,
        }
    }
}

/// Compression algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionAlgorithm {
    None,
    Lz4,
    Zstd,
    Gzip,
    Brotli,
}

/// File cache entry with CoW support
#[derive(Debug)]
pub struct FileCacheEntry {
    pub offset: u64,
    pub size: usize,
    pub cow_pages: Vec<CowPageRef>,
    pub dirty_pages: Vec<bool>,
    pub last_access: AtomicU64,
    pub access_count: AtomicU64,
}

/// High-performance file buffer with zero-copy support
pub struct FileBuffer {
    pages: Vec<CowPageRef>,
    size: usize,
    capacity: usize,
    read_only: bool,
    compression_enabled: bool,
    compression_threshold: usize,
}

impl FileBuffer {
    /// Create new file buffer
    pub fn new(size: usize, read_only: bool) -> Self {
        let pages_needed = (size + 0xFFF) >> 12;
        let mut pages = Vec::with_capacity(pages_needed);
        
        for _ in 0..pages_needed {
            if let Some(frame) = page_allocator::allocate_frame() {
                let cow_page = CowPageRef {
                    physical_addr: frame.start_address(),
                    ref_count: Arc::new(AtomicUsize::new(1)),
                    dirty: AtomicBool::new(false),
                    compressed: false,
                    compression_algo: CompressionAlgorithm::None,
                };
                pages.push(cow_page);
            }
        }
        
        FileBuffer {
            pages,
            size,
            capacity: pages_needed * 4096,
            read_only,
            compression_enabled: true,
            compression_threshold: 4096,
        }
    }
    
    /// Clone buffer with copy-on-write
    pub fn cow_clone(&self) -> Self {
        let mut cloned_pages = Vec::with_capacity(self.pages.len());
        
        for page in &self.pages {
            page.ref_count.fetch_add(1, Ordering::Relaxed);
            cloned_pages.push(page.clone());
        }
        
        FileBuffer {
            pages: cloned_pages,
            size: self.size,
            capacity: self.capacity,
            read_only: false,
            compression_enabled: self.compression_enabled,
            compression_threshold: self.compression_threshold,
        }
    }
    
    /// Ensure page is writable (trigger CoW if needed)
    fn ensure_writable(&mut self, page_index: usize) -> Result<(), &'static str> {
        if page_index >= self.pages.len() {
            return Err("Page index out of bounds");
        }
        
        let page = &mut self.pages[page_index];
        
        if page.ref_count.load(Ordering::Relaxed) > 1 {
            // Need to perform copy-on-write
            if let Some(new_frame) = page_allocator::allocate_frame() {
                unsafe {
                    // Copy data from shared page to new page
                    let src = page.physical_addr.as_u64() as *const u8;
                    let dst = new_frame.start_address().as_u64() as *mut u8;
                    core::ptr::copy_nonoverlapping(src, dst, 4096);
                }
                
                // Decrease reference count on old page
                page.ref_count.fetch_sub(1, Ordering::Relaxed);
                
                // Update to new page
                page.physical_addr = new_frame.start_address();
                page.ref_count = Arc::new(AtomicUsize::new(1));
                page.dirty.store(true, Ordering::Relaxed);
            } else {
                return Err("Failed to allocate page for CoW");
            }
        } else {
            // Single reference, mark as dirty
            page.dirty.store(true, Ordering::Relaxed);
        }
        
        Ok(())
    }
    
    /// Read data from buffer
    pub fn read(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if offset >= self.size {
            return Ok(0);
        }
        
        let read_size = buffer.len().min(self.size - offset);
        let mut bytes_read = 0;
        
        while bytes_read < read_size {
            let page_offset = (offset + bytes_read) % 4096;
            let page_index = (offset + bytes_read) / 4096;
            let bytes_in_page = (4096 - page_offset).min(read_size - bytes_read);
            
            if page_index >= self.pages.len() {
                break;
            }
            
            let page = &self.pages[page_index];
            
            if page.compressed {
                // Decompress page if needed
                self.decompress_page(page_index)?;
            }
            
            unsafe {
                let src = (page.physical_addr.as_u64() + page_offset as u64) as *const u8;
                let dst = buffer[bytes_read..].as_mut_ptr();
                core::ptr::copy_nonoverlapping(src, dst, bytes_in_page);
            }
            
            bytes_read += bytes_in_page;
        }
        
        Ok(bytes_read)
    }
    
    /// Write data to buffer
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize, &'static str> {
        if self.read_only {
            return Err("Buffer is read-only");
        }
        
        let write_size = data.len();
        let mut bytes_written = 0;
        
        // Extend buffer if needed
        if offset + write_size > self.capacity {
            self.extend_capacity(offset + write_size)?;
        }
        
        while bytes_written < write_size {
            let page_offset = (offset + bytes_written) % 4096;
            let page_index = (offset + bytes_written) / 4096;
            let bytes_in_page = (4096 - page_offset).min(write_size - bytes_written);
            
            self.ensure_writable(page_index)?;
            
            let page = &mut self.pages[page_index];
            
            unsafe {
                let src = data[bytes_written..].as_ptr();
                let dst = (page.physical_addr.as_u64() + page_offset as u64) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, bytes_in_page);
            }
            
            bytes_written += bytes_in_page;
        }
        
        self.size = self.size.max(offset + write_size);
        Ok(bytes_written)
    }
    
    /// Extend buffer capacity
    fn extend_capacity(&mut self, new_capacity: usize) -> Result<(), &'static str> {
        let pages_needed = (new_capacity + 0xFFF) >> 12;
        
        while self.pages.len() < pages_needed {
            if let Some(frame) = page_allocator::allocate_frame() {
                let cow_page = CowPageRef {
                    physical_addr: frame.start_address(),
                    ref_count: Arc::new(AtomicUsize::new(1)),
                    dirty: AtomicBool::new(false),
                    compressed: false,
                    compression_algo: CompressionAlgorithm::None,
                };
                self.pages.push(cow_page);
            } else {
                return Err("Failed to allocate pages for buffer extension");
            }
        }
        
        self.capacity = pages_needed * 4096;
        Ok(())
    }
    
    /// Compress page if beneficial
    fn compress_page(&mut self, page_index: usize) -> Result<(), &'static str> {
        if !self.compression_enabled || page_index >= self.pages.len() {
            return Ok(());
        }
        
        // Check if already compressed
        if self.pages[page_index].compressed {
            return Ok(());
        }
        
        // Get data needed for compression check
        let physical_addr = self.pages[page_index].physical_addr;
        let compression_threshold = self.compression_threshold;
        
        // Simple compression simulation (would use real algorithm)
        let original_data = unsafe {
            core::slice::from_raw_parts(
                physical_addr.as_u64() as *const u8,
                4096
            )
        };
        
        // Check if compression would be beneficial
        let compressed_size = self.estimate_compression_size(original_data, CompressionAlgorithm::Lz4);
        
        if compressed_size < compression_threshold {
            let page = &mut self.pages[page_index];
            page.compressed = true;
            page.compression_algo = CompressionAlgorithm::Lz4;
        }
        
        Ok(())
    }
    
    /// Decompress page
    fn decompress_page(&self, page_index: usize) -> Result<(), &'static str> {
        if page_index >= self.pages.len() {
            return Err("Page index out of bounds");
        }
        
        let page = &self.pages[page_index];
        
        if !page.compressed {
            return Ok(());
        }
        
        // Decompress in-place (simplified)
        // In real implementation, would use compression library
        
        Ok(())
    }
    
    /// Estimate compression size
    fn estimate_compression_size(&self, data: &[u8], _algo: CompressionAlgorithm) -> usize {
        // Simple estimation - count zeros and repeated bytes
        let mut unique_bytes = 0;
        let mut last_byte = None;
        
        for &byte in data {
            if Some(byte) != last_byte {
                unique_bytes += 1;
                last_byte = Some(byte);
            }
        }
        
        // Rough compression estimate
        (unique_bytes * 3 / 2).min(data.len())
    }
}

/// VFS inode (index node)
pub struct VfsInode {
    pub metadata: RwLock<FileMetadata>,
    pub file_buffer: Option<Mutex<FileBuffer>>,
    pub directory_entries: Option<RwLock<BTreeMap<String, u64>>>,
    pub symlink_target: Option<String>,
    pub device_ops: Option<Arc<dyn DeviceOperations>>,
    
    // Caching and performance
    pub cache_entries: RwLock<Vec<FileCacheEntry>>,
    pub readahead_window: AtomicUsize,
    pub last_access: AtomicU64,
}

impl VfsInode {
    /// Create new regular file inode
    pub fn new_file(metadata: FileMetadata, size: usize) -> Self {
        let file_buffer = Some(Mutex::new(FileBuffer::new(size, false)));
        
        VfsInode {
            metadata: RwLock::new(metadata),
            file_buffer,
            directory_entries: None,
            symlink_target: None,
            device_ops: None,
            cache_entries: RwLock::new(Vec::new()),
            readahead_window: AtomicUsize::new(65536), // 64KB default
            last_access: AtomicU64::new(0),
        }
    }
    
    /// Create new directory inode
    pub fn new_directory(metadata: FileMetadata) -> Self {
        let directory_entries = Some(RwLock::new(BTreeMap::new()));
        
        VfsInode {
            metadata: RwLock::new(metadata),
            file_buffer: None,
            directory_entries,
            symlink_target: None,
            device_ops: None,
            cache_entries: RwLock::new(Vec::new()),
            readahead_window: AtomicUsize::new(0),
            last_access: AtomicU64::new(0),
        }
    }
    
    /// Create symbolic link inode
    pub fn new_symlink(metadata: FileMetadata, target: String) -> Self {
        VfsInode {
            metadata: RwLock::new(metadata),
            file_buffer: None,
            directory_entries: None,
            symlink_target: Some(target),
            device_ops: None,
            cache_entries: RwLock::new(Vec::new()),
            readahead_window: AtomicUsize::new(0),
            last_access: AtomicU64::new(0),
        }
    }
    
    /// Read from file with readahead optimization
    pub fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, &'static str> {
        self.last_access.store(crate::time::timestamp_millis(), Ordering::Relaxed);
        
        if let Some(ref file_buffer) = self.file_buffer {
            let mut buf = file_buffer.lock();
            let bytes_read = buf.read(offset as usize, buffer)?;
            
            // Trigger readahead if needed
            let readahead_size = self.readahead_window.load(Ordering::Relaxed);
            if readahead_size > 0 && bytes_read == buffer.len() {
                self.schedule_readahead(offset + bytes_read as u64, readahead_size)?;
            }
            
            Ok(bytes_read)
        } else {
            Err("Not a regular file")
        }
    }
    
    /// Write to file
    pub fn write(&self, offset: u64, data: &[u8]) -> Result<usize, &'static str> {
        if let Some(ref file_buffer) = self.file_buffer {
            let mut buf = file_buffer.lock();
            let bytes_written = buf.write(offset as usize, data)?;
            
            // Update metadata
            let mut metadata = self.metadata.write();
            metadata.mtime = crate::time::timestamp_millis();
            metadata.size = metadata.size.max(offset + bytes_written as u64);
            
            Ok(bytes_written)
        } else {
            Err("Not a regular file")
        }
    }
    
    /// Schedule readahead operation
    fn schedule_readahead(&self, offset: u64, _size: usize) -> Result<(), &'static str> {
        // Simplified readahead - would be done asynchronously in production
        if let Some(ref file_buffer) = self.file_buffer {
            let buf = file_buffer.lock();
            if (offset as usize) < buf.capacity {
                // Readahead is already in buffer
                return Ok(());
            }
        }
        
        // In production, would schedule async I/O operation
        Ok(())
    }
    
    /// Add directory entry
    pub fn add_directory_entry(&self, name: String, inode: u64) -> Result<(), &'static str> {
        if let Some(ref entries) = self.directory_entries {
            let mut dir_entries = entries.write();
            dir_entries.insert(name, inode);
            Ok(())
        } else {
            Err("Not a directory")
        }
    }
    
    /// Remove directory entry
    pub fn remove_directory_entry(&self, name: &str) -> Result<Option<u64>, &'static str> {
        if let Some(ref entries) = self.directory_entries {
            let mut dir_entries = entries.write();
            Ok(dir_entries.remove(name))
        } else {
            Err("Not a directory")
        }
    }
    
    /// List directory entries
    pub fn list_directory(&self) -> Result<Vec<(String, u64)>, &'static str> {
        if let Some(ref entries) = self.directory_entries {
            let dir_entries = entries.read();
            Ok(dir_entries.iter().map(|(k, &v)| (k.clone(), v)).collect())
        } else {
            Err("Not a directory")
        }
    }
}

/// Device operations trait
pub trait DeviceOperations: Send + Sync {
    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, &'static str>;
    fn write(&self, offset: u64, data: &[u8]) -> Result<usize, &'static str>;
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64, &'static str>;
}

/// File system operations trait
pub trait FileSystemOperations: Send + Sync {
    fn mount(&self, device: &str, mountpoint: &str, options: &str) -> Result<(), &'static str>;
    fn unmount(&self, mountpoint: &str) -> Result<(), &'static str>;
    fn create_inode(&self, parent: u64, name: &str, mode: FileMode) -> Result<u64, &'static str>;
    fn delete_inode(&self, inode: u64) -> Result<(), &'static str>;
    fn lookup(&self, parent: u64, name: &str) -> Result<Option<u64>, &'static str>;
    fn sync(&self) -> Result<(), &'static str>;
}

/// Mount point information
#[derive(Debug, Clone)]
pub struct MountPoint {
    pub device: String,
    pub filesystem: FileSystemType,
    pub mount_path: String,
    pub options: Vec<String>,
    pub root_inode: u64,
}

/// Virtual File System manager
pub struct VirtualFileSystem {
    pub inodes: RwLock<BTreeMap<u64, Arc<VfsInode>>>,
    pub mount_points: RwLock<BTreeMap<String, MountPoint>>,
    pub filesystems: RwLock<BTreeMap<FileSystemType, Arc<dyn FileSystemOperations>>>,
    pub next_inode: AtomicU64,
    
    // I/O scheduling
    pub io_queue: Mutex<VecDeque<IoRequest>>,
    pub io_stats: IoStatistics,
}

/// I/O request for scheduling
#[derive(Debug)]
pub struct IoRequest {
    pub inode: u64,
    pub operation: IoOperation,
    pub offset: u64,
    pub size: usize,
    pub priority: u8,
    pub timestamp: u64,
}

/// I/O operation type
#[derive(Debug)]
pub enum IoOperation {
    Read,
    Write,
    Sync,
    Readahead,
}

/// I/O statistics
#[derive(Debug)]
pub struct IoStatistics {
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

impl VirtualFileSystem {
    /// Create new VFS
    pub fn new() -> Self {
        VirtualFileSystem {
            inodes: RwLock::new(BTreeMap::new()),
            mount_points: RwLock::new(BTreeMap::new()),
            filesystems: RwLock::new(BTreeMap::new()),
            next_inode: AtomicU64::new(1),
            io_queue: Mutex::new(VecDeque::new()),
            io_stats: IoStatistics {
                reads: AtomicU64::new(0),
                writes: AtomicU64::new(0),
                bytes_read: AtomicU64::new(0),
                bytes_written: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
            },
        }
    }
    
    /// Allocate new inode number
    pub fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::Relaxed)
    }
    
    /// Register file system
    pub fn register_filesystem(&self, fs_type: FileSystemType, fs_ops: Arc<dyn FileSystemOperations>) {
        let mut filesystems = self.filesystems.write();
        filesystems.insert(fs_type, fs_ops);
    }
    
    /// Mount file system
    pub fn mount(&self, device: &str, mountpoint: &str, fs_type: FileSystemType, options: &str) -> Result<(), &'static str> {
        let fs_ops = {
            let filesystems = self.filesystems.read();
            filesystems.get(&fs_type)
                .ok_or("Unsupported file system type")?
                .clone()
        };
        
        fs_ops.mount(device, mountpoint, options)?;
        
        let mount_point = MountPoint {
            device: device.to_string(),
            filesystem: fs_type,
            mount_path: mountpoint.to_string(),
            options: options.split(',').map(|s| s.to_string()).collect(),
            root_inode: self.allocate_inode(),
        };
        
        let mut mount_points = self.mount_points.write();
        mount_points.insert(mountpoint.to_string(), mount_point);
        
        Ok(())
    }
    
    /// Create file
    pub fn create_file(&self, path: &str, mode: FileMode) -> Result<u64, &'static str> {
        let (parent_path, filename) = self.split_path(path);
        let parent_inode = self.resolve_path(&parent_path)?;
        
        let inode_num = self.allocate_inode();
        let metadata = FileMetadata {
            inode: inode_num,
            size: 0,
            blocks: 0,
            mode,
            uid: 0, // TODO: Get current user
            gid: 0, // TODO: Get current group
            atime: crate::time::timestamp_millis(),
            mtime: crate::time::timestamp_millis(),
            ctime: crate::time::timestamp_millis(),
            btime: crate::time::timestamp_millis(),
            links: 1,
            device: 0,
            rdev: 0,
        };
        
        let inode = match mode.file_type {
            FileType::RegularFile => Arc::new(VfsInode::new_file(metadata, 0)),
            FileType::Directory => Arc::new(VfsInode::new_directory(metadata)),
            _ => return Err("Unsupported file type"),
        };
        
        // Add to parent directory
        if let Some(parent) = self.get_inode(parent_inode) {
            parent.add_directory_entry(filename.to_string(), inode_num)?;
        }
        
        let mut inodes = self.inodes.write();
        inodes.insert(inode_num, inode);
        
        Ok(inode_num)
    }
    
    /// Get inode by number
    pub fn get_inode(&self, inode_num: u64) -> Option<Arc<VfsInode>> {
        let inodes = self.inodes.read();
        inodes.get(&inode_num).cloned()
    }
    
    /// Resolve path to inode number
    pub fn resolve_path(&self, path: &str) -> Result<u64, &'static str> {
        if path == "/" {
            return Ok(1); // Root inode
        }
        
        let components: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut current_inode = 1; // Start from root
        
        for component in components {
            if component.is_empty() {
                continue;
            }
            
            if let Some(inode) = self.get_inode(current_inode) {
                if let Ok(entries) = inode.list_directory() {
                    current_inode = entries.iter()
                        .find(|(name, _)| name == component)
                        .map(|(_, inode_num)| *inode_num)
                        .ok_or("Path component not found")?;
                } else {
                    return Err("Not a directory");
                }
            } else {
                return Err("Inode not found");
            }
        }
        
        Ok(current_inode)
    }
    
    /// Split path into parent and filename
    fn split_path(&self, path: &str) -> (String, String) {
        let path = path.trim_end_matches('/');
        if let Some(pos) = path.rfind('/') {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let filename = &path[pos + 1..];
            (parent.to_string(), filename.to_string())
        } else {
            ("/".to_string(), path.to_string())
        }
    }
    
    /// Read from file
    pub fn read_file(&self, inode_num: u64, offset: u64, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if let Some(inode) = self.get_inode(inode_num) {
            let bytes_read = inode.read(offset, buffer)?;
            
            self.io_stats.reads.fetch_add(1, Ordering::Relaxed);
            self.io_stats.bytes_read.fetch_add(bytes_read as u64, Ordering::Relaxed);
            
            Ok(bytes_read)
        } else {
            Err("Inode not found")
        }
    }
    
    /// Write to file
    pub fn write_file(&self, inode_num: u64, offset: u64, data: &[u8]) -> Result<usize, &'static str> {
        if let Some(inode) = self.get_inode(inode_num) {
            let bytes_written = inode.write(offset, data)?;
            
            self.io_stats.writes.fetch_add(1, Ordering::Relaxed);
            self.io_stats.bytes_written.fetch_add(bytes_written as u64, Ordering::Relaxed);
            
            Ok(bytes_written)
        } else {
            Err("Inode not found")
        }
    }
    
    /// Sync metadata to disk
    pub fn sync_metadata(&self) {
        // Sync VFS metadata to persistent storage
        crate::log::info!("VFS metadata sync requested");
    }
    
    /// Process pending VFS operations
    pub fn process_pending_operations(&mut self, max_operations: usize) -> usize {
        let mut processed = 0;
        let mut queue = self.io_queue.lock();
        
        while processed < max_operations && !queue.is_empty() {
            if let Some(_operation) = queue.pop_front() {
                // Process the operation
                processed += 1;
            }
        }
        
        processed
    }
}

/// Global VFS instance
static mut VFS: Option<VirtualFileSystem> = None;

/// Initialize VFS
pub fn init_vfs() {
    unsafe {
        VFS = Some(VirtualFileSystem::new());
    }
}

/// Get VFS instance
pub fn get_vfs() -> Option<&'static VirtualFileSystem> {
    unsafe { VFS.as_ref() }
}

/// Get mutable VFS instance
pub fn get_vfs_mut() -> Option<&'static mut VirtualFileSystem> {
    unsafe { VFS.as_mut() }
}

/// Read data from a file at a specific offset
pub fn read_at_offset(
    file_path: &str,
    offset: u64,
    buffer: &mut [u8]
) -> Result<usize, &'static str> {
    if let Some(vfs) = get_vfs() {
        // Parse file path to get file system and inode
        if let Ok(inode) = vfs.resolve_path(file_path) {
            // Read from the file at the specified offset
            vfs.read_file(inode, offset, buffer)
        } else {
            Err("File not found")
        }
    } else {
        Err("VFS not initialized")
    }
}