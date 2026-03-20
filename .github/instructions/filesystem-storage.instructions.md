---
applyTo: "src/fs/**,src/storage/**,src/persistence/**"
---

# Filesystem & Storage — NONOS Kernel

## Architecture

```
VFS Layer          src/fs/              Virtual filesystem, mount points, inodes, fd ops
                   src/fs/cryptofs/     Per-file encryption (AES-GCM)
Cache Layer        src/fs/cache/        File cache, page cache, stats
Block Layer        src/storage/         Block device abstraction, partition tables
Driver Layer       src/drivers/ahci/    SATA (AHCI)
                   src/drivers/nvme/    NVMe
Persistence        src/persistence/     Persistent key-value store, journal
```

## VFS Interface

All filesystem operations go through the VFS layer:

```rust
// File operations
pub fn vfs_open(path: &str, flags: OpenFlags) -> Result<Fd, FsError>;
pub fn vfs_read(fd: Fd, buf: &mut [u8]) -> Result<usize, FsError>;
pub fn vfs_write(fd: Fd, data: &[u8]) -> Result<usize, FsError>;
pub fn vfs_close(fd: Fd) -> Result<(), FsError>;
pub fn vfs_stat(path: &str) -> Result<Stat, FsError>;

// Directory operations
pub fn vfs_mkdir(path: &str) -> Result<(), FsError>;
pub fn vfs_readdir(path: &str) -> Result<Vec<DirEntry>, FsError>;

// Mount
pub fn vfs_mount(device: &str, mountpoint: &str, fstype: &str) -> Result<(), FsError>;
```

## CryptoFS — Encrypted Filesystem

Location: `src/fs/cryptofs/`

Every file is encrypted at rest with AES-256-GCM:

```rust
pub struct CryptoFile {
    pub inode: u64,
    pub key: [u8; 32],        // Per-file key (derived from master key + inode)
    pub nonce_counter: u64,   // Monotonic nonce for each write
}
```

### Key Derivation

```
Master Key (sealed in TPM)
└── HKDF-SHA256(master_key, salt=inode_id) → per-file key
```

### Write Path

```
plaintext → AES-256-GCM encrypt (per-file key, nonce) → ciphertext + tag → block device
```

### Read Path

```
block device → ciphertext + tag → AES-256-GCM decrypt → plaintext
```

**Nonce management:** Each file has a monotonic write counter. Nonce = counter value. Counter is persisted in the file's metadata block. **Never reuse a nonce** — if the counter is lost, the file key must be rotated.

### Key Rotation

```rust
pub fn rotate_file_key(inode: u64) -> Result<(), CryptoFsError> {
    let old_key = derive_file_key(inode)?;
    let new_master = generate_new_master_key()?;
    let new_key = derive_file_key_with(new_master, inode)?;

    // Re-encrypt all blocks with new key
    for block in read_all_blocks(inode)? {
        let plaintext = decrypt_block(&old_key, &block)?;
        let ciphertext = encrypt_block(&new_key, &plaintext)?;
        write_block(inode, &ciphertext)?;
    }

    // Zeroize old key
    zeroize(&old_key);
    Ok(())
}
```

## Block Device Layer

Location: `src/storage/`

```rust
pub trait BlockDevice {
    fn read_block(&self, lba: u64, buf: &mut [u8]) -> Result<(), StorageError>;
    fn write_block(&self, lba: u64, data: &[u8]) -> Result<(), StorageError>;
    fn block_size(&self) -> u32;      // Usually 512
    fn total_blocks(&self) -> u64;
}
```

### LBA Validation

**All LBA access must go through `drivers::security::lba::validate_lba_range()`:**

```rust
validate_lba_range(lba, count)?;  // Bounds check before I/O /

// SAFETY: LBA range validated above
driver.read_blocks(lba, count, &mut buf)?;
```

## Partition Table Support

FAT32 and GPT partition table parsing in `src/storage/`:

```rust
pub fn detect_partitions(device: &dyn BlockDevice) -> Result<Vec<Partition>, StorageError> {
    // Try GPT first, fall back to MBR
    if let Ok(gpt) = parse_gpt(device) {
        return Ok(gpt.partitions);
    }
    parse_mbr(device).map(|mbr| mbr.partitions)
}
```

## POSIX File Descriptor Layer

Location: `src/fs/fd/`

```rust
pub struct FileDescriptorTable {
    fds: BTreeMap<Fd, FileDescription>,
}

pub struct FileDescription {
    pub file: Arc<VfsFile>,
    pub offset: u64,
    pub flags: OpenFlags,
}
```

- `Fd` is a newtype around `u32`
- Per-process fd table (not shared unless `CLONE_FILES`)
- Standard fds: 0=stdin, 1=stdout, 2=stderr

## File Cache

Location: `src/fs/cache/`

- Page cache: maps (inode, offset) → cached page frame
- Write-back policy: dirty pages flushed on sync or eviction
- LRU eviction when memory pressure occurs
- Cache bypass for O_DIRECT

## Common Pitfalls

1. **Nonce reuse in CryptoFS** — catastrophic: allows key recovery. Always increment counter.
2. **LBA out of bounds** — validate before every I/O operation
3. **Double-close** — closing an already-closed fd must return EBADF, not crash
4. **Path traversal** — validate that resolved path doesn't escape mount root (`../../../etc`)
5. **Large file on small device** — check available blocks before allocating
6. **Cache coherency** — flush cache before reading from device if another path may have written
7. **Forgetting to zeroize file keys** — per-file keys must be zeroized when file is closed
