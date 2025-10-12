#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use spin::Once;

// Core types exposed to fs::mod
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemType {
    RamFs,
    CryptoFS,
    TmpFs,
    ProcFs,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    None,
    Lz4,
    Zstd,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub file_type: FileType,
    pub mode: FileMode,
}

#[derive(Debug, Clone)]
pub struct VfsInode(pub u64);

#[derive(Debug, Clone)]
pub struct FileBuffer {
    pub data: alloc::vec::Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CowPageRef {
    pub id: u64,
}

#[derive(Debug, Clone)]
pub struct FileCacheEntry {
    pub inode: VfsInode,
    pub dirty: bool,
}

#[derive(Debug, Clone)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Fsync,
}

#[derive(Debug, Clone)]
pub struct IoRequest {
    pub op: IoOperation,
    pub inode: VfsInode,
    pub offset: u64,
    pub len: usize,
}

#[derive(Debug, Default, Clone)]
pub struct IoStatistics {
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
}

#[derive(Debug, Clone)]
pub struct MountPoint {
    pub mount_path: String,
    pub filesystem: FileSystemType,
}

pub trait FileSystemOperations {
    fn sync_metadata(&self);
    fn process_pending_operations(&self, max_ops: usize) -> usize;
}

pub trait DeviceOperations {
    fn flush(&self) -> Result<(), &'static str>;
}

#[derive(Debug)]
struct VirtualFileSystemInner {
    mounts: Vec<MountPoint>,
    pending_ops: usize,
    io_stats: IoStatistics,
}

#[derive(Debug)]
pub struct VirtualFileSystem {
    inner: spin::Mutex<VirtualFileSystemInner>,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        Self {
            inner: spin::Mutex::new(VirtualFileSystemInner {
                mounts: Vec::new(),
                pending_ops: 0,
                io_stats: IoStatistics::default(),
            }),
        }
    }

    pub fn sync_metadata(&self) {
        let _g = self.inner.lock();
        // Nothing to persist in RAM-only mode.
    }

    pub fn process_pending_operations(&self, max_ops: usize) -> usize {
        let mut g = self.inner.lock();
        let to_process = core::cmp::min(g.pending_ops, max_ops);
        g.pending_ops -= to_process;
        to_process
    }

    pub fn mount(&self, mount_path: &str, fs_type: FileSystemType) {
        let mut g = self.inner.lock();
        g.mounts.push(MountPoint { mount_path: mount_path.into(), filesystem: fs_type });
    }

    pub fn mounts(&self) -> Vec<MountPoint> {
        let g = self.inner.lock();
        g.mounts.clone()
    }
}

static VFS: Once<VirtualFileSystem> = Once::new();

pub fn init_vfs() {
    VFS.call_once(|| {
        let vfs = VirtualFileSystem::new();
        // Mount RAM FS at root by default
        vfs.mount("/", FileSystemType::RamFs);
        vfs
    });
}

pub fn get_vfs() -> Option<&'static VirtualFileSystem> {
    VFS.get()
}

pub fn get_vfs_mut() -> Option<&'static VirtualFileSystem> {
    // interior mutability is used.
    VFS.get()
}
