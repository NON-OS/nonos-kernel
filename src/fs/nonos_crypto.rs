#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec, string::ToString};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};

#[derive(Debug, Default, Clone)]
pub struct CryptoFsStatistics {
    pub files: u64,
    pub bytes_stored: u64,
}

#[derive(Debug)]
pub struct CryptoFileSystem {
    inner: Mutex<CryptoInner>,
    stats: Mutex<CryptoFsStatistics>,
}

#[derive(Debug)]
struct CryptoInner {
    block_size: usize,
    total_blocks: usize,
    files: BTreeMap<String, FileEntry>,
    next_inode: AtomicU64,
}

#[derive(Debug, Clone)]
struct FileEntry {
    inode: u64,
    key: Vec<u8>,
    encrypted: Vec<u8>,
}

static CRYPTOFS: Once<CryptoFileSystem> = Once::new();

pub fn init_cryptofs(total_blocks: usize, block_size: usize) -> Result<(), &'static str> {
    CRYPTOFS.call_once(|| {
        CryptoFileSystem {
            inner: Mutex::new(CryptoInner {
                block_size,
                total_blocks,
                files: BTreeMap::new(),
                next_inode: AtomicU64::new(3),
            }),
            stats: Mutex::new(CryptoFsStatistics::default()),
        }
    });
    Ok(())
}

pub fn get_cryptofs() -> Option<&'static CryptoFileSystem> {
    CRYPTOFS.get()
}

impl CryptoFileSystem {
    pub fn sync_all(&self) {}

    pub fn process_pending_operations(&self, _max_ops: usize) -> usize {
        0
    }

    pub fn stats(&self) -> CryptoFsStatistics {
        self.stats.lock().clone()
    }
}

fn derive_key(path: &str) -> Vec<u8> {
    let mut key = Vec::new();
    for (i, b) in path.bytes().enumerate() {
        key.push(b ^ 0x5A ^ ((i as u8) << 1));
    }
    while key.len() < 32 {
        key.push(0xA5);
    }
    key
}

fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, &byte) in data.iter().enumerate() {
        out.push(byte ^ key[i % key.len()].rotate_left((i % 8) as u32));
    }
    out
}

pub fn create_encrypted_file(_parent_inode: u64, path: &str, _caps: &[u8]) -> Result<u64, &'static str> {
    let fs = CRYPTOFS.get().ok_or("CryptoFS not initialized")?;
    let key = derive_key(path);

    let mut inner = fs.inner.lock();
    if inner.files.contains_key(path) {
        return Ok(inner.files[path].inode);
    }

    let inode = inner.next_inode.fetch_add(1, Ordering::Relaxed);
    inner.files.insert(path.into(), FileEntry { inode, key: key.clone(), encrypted: Vec::new() });

    let mut st = fs.stats.lock();
    st.files += 1;

    Ok(inode)
}

pub fn create_ephemeral_file(path: &str, data: &[u8]) -> Result<u64, &'static str> {
    let fs = CRYPTOFS.get().ok_or("CryptoFS not initialized")?;
    let key = derive_key(path);
    let mut inner = fs.inner.lock();

    let inode = inner.next_inode.fetch_add(1, Ordering::Relaxed);
    let enc = xor_cipher(data, &key);
    inner.files.insert(path.into(), FileEntry { inode, key: key.clone(), encrypted: enc });

    let mut st = fs.stats.lock();
    st.files += 1;
    st.bytes_stored += data.len() as u64;

    Ok(inode)
}

pub fn read_encrypted(path: &str) -> Result<Vec<u8>, &'static str> {
    let fs = CRYPTOFS.get().ok_or("CryptoFS not initialized")?;
    let inner = fs.inner.lock();
    let entry = inner.files.get(path).ok_or("Not found")?;
    Ok(xor_cipher(&entry.encrypted, &entry.key))
}

pub fn write_encrypted(path: &str, data: &[u8]) -> Result<(), &'static str> {
    let fs = CRYPTOFS.get().ok_or("CryptoFS not initialized")?;
    let mut inner = fs.inner.lock();

    if !inner.files.contains_key(path) {
        drop(inner);
        let _ = create_ephemeral_file(path, data)?;
        return Ok(());
    }

    let entry = inner.files.get_mut(path).ok_or("Not found")?;
    entry.encrypted = xor_cipher(data, &entry.key);

    let mut st = fs.stats.lock();
    st.bytes_stored += data.len() as u64;
    Ok(())
}

pub fn delete_encrypted(path: &str) -> Result<(), &'static str> {
    let fs = CRYPTOFS.get().ok_or("CryptoFS not initialized")?;
    let mut inner = fs.inner.lock();
    if let Some(mut entry) = inner.files.remove(path) {
        for b in entry.encrypted.iter_mut() {
            *b = 0;
        }
        for b in entry.key.iter_mut() {
            *b = 0;
        }
        let mut st = fs.stats.lock();
        st.files = st.files.saturating_sub(1);
        return Ok(());
    }
    Err("Not found")
}
