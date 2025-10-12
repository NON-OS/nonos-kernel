#![no_std]

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Mutex, RwLock};

#[derive(Debug, Clone, Copy)]
pub enum NonosFileSystemType {
    QuantumSafe = 0,
    Encrypted = 1,
    Ephemeral = 2,
}

#[derive(Debug)]
pub struct NonosFilesystem {
    filesystem_type: NonosFileSystemType,
    files: RwLock<BTreeMap<String, NonosFile>>,
    quantum_keys: Mutex<BTreeMap<String, Vec<u8>>>,
    encryption_enabled: bool,
}

#[derive(Debug)]
pub struct NonosFile {
    pub name: String,
    pub data: Vec<u8>,
    pub size: usize,
    pub created: u64,
    pub modified: u64,
    pub encrypted: bool,
    pub quantum_protected: bool,
}

impl NonosFilesystem {
    pub const fn new() -> Self {
        Self {
            filesystem_type: NonosFileSystemType::Ephemeral, // RAM-only default
            files: RwLock::new(BTreeMap::new()),
            quantum_keys: Mutex::new(BTreeMap::new()),
            encryption_enabled: true,
        }
    }

    pub fn create_file(&self, name: &str, data: &[u8]) -> Result<(), &'static str> {
        let timestamp = self.get_timestamp();

        let stored = if self.encryption_enabled {
            let _ = self.ensure_key(name)?;
            self.encrypt_file_data(data, name)?
        } else {
            data.to_vec()
        };

        let file = NonosFile {
            name: String::from(name),
            size: data.len(),
            data: stored,
            created: timestamp,
            modified: timestamp,
            encrypted: self.encryption_enabled,
            quantum_protected: matches!(self.filesystem_type, NonosFileSystemType::QuantumSafe),
        };

        self.files.write().insert(String::from(name), file);
        Ok(())
    }

    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, &'static str> {
        let files = self.files.read();
        let file = files.get(name).ok_or("File not found")?;

        if file.encrypted {
            self.decrypt_file_data(&file.data, name)
        } else {
            Ok(file.data.clone())
        }
    }

    pub fn write_file(&self, name: &str, data: &[u8]) -> Result<(), &'static str> {
        let mut files = self.files.write();
        let file = files.get_mut(name).ok_or("File not found")?;

        let stored = if self.encryption_enabled {
            let _ = self.ensure_key(name)?;
            self.encrypt_file_data(data, name)?
        } else {
            data.to_vec()
        };

        file.data = stored;
        file.size = data.len();
        file.modified = self.get_timestamp();
        Ok(())
    }

    pub fn delete_file(&self, name: &str) -> Result<(), &'static str> {
        // Zeroize contents before removal
        {
            let mut files = self.files.write();
            let file = files.get_mut(name).ok_or("File not found")?;
            for b in file.data.iter_mut() {
                *b = 0;
            }
        }
        self.files.write().remove(name).ok_or("File not found")?;

        if let Some(mut key) = self.quantum_keys.lock().remove(name) {
            for b in key.iter_mut() {
                *b = 0;
            }
        }
        Ok(())
    }

    pub fn list_files(&self) -> Vec<String> {
        self.files.read().keys().cloned().collect()
    }

    fn ensure_key(&self, filename: &str) -> Result<(), &'static str> {
        let mut keys = self.quantum_keys.lock();
        if !keys.contains_key(filename) {
            let key = self.generate_quantum_key(filename)?;
            keys.insert(String::from(filename), key);
        }
        Ok(())
    }

    fn generate_quantum_key(&self, filename: &str) -> Result<Vec<u8>, &'static str> {
        // Obfuscation key for RAM-only mode
        let mut key = Vec::new();
        for (i, byte) in filename.bytes().enumerate() {
            key.push(byte ^ (i as u8) ^ 0xAA);
        }
        while key.len() < 32 {
            key.push(0x55);
        }
        Ok(key)
    }

    fn encrypt_file_data(&self, data: &[u8], filename: &str) -> Result<Vec<u8>, &'static str> {
        let keys = self.quantum_keys.lock();
        let key = keys.get(filename).ok_or("No encryption key found")?;

        let mut encrypted = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            encrypted.push(byte ^ key_byte.rotate_left((i % 8) as u32));
        }
        Ok(encrypted)
    }

    fn decrypt_file_data(&self, encrypted_data: &[u8], filename: &str) -> Result<Vec<u8>, &'static str> {
        self.encrypt_file_data(encrypted_data, filename)
    }

    fn get_timestamp(&self) -> u64 {
        crate::time::current_ticks()
    }

    pub fn get_file_info(&self, name: &str) -> Result<NonosFileInfo, &'static str> {
        let files = self.files.read();
        let file = files.get(name).ok_or("File not found")?;

        Ok(NonosFileInfo {
            name: file.name.clone(),
            size: file.size,
            created: file.created,
            modified: file.modified,
            encrypted: file.encrypted,
            quantum_protected: file.quantum_protected,
        })
    }
}

#[derive(Debug)]
pub struct NonosFileInfo {
    pub name: String,
    pub size: usize,
    pub created: u64,
    pub modified: u64,
    pub encrypted: bool,
    pub quantum_protected: bool,
}

// Global filesystem instance
pub static NONOS_FILESYSTEM: NonosFilesystem = NonosFilesystem::new();

pub fn init_nonos_filesystem() -> Result<(), &'static str> {
    Ok(())
}

pub fn create_file(name: &str, data: &[u8]) -> Result<(), &'static str> {
    NONOS_FILESYSTEM.create_file(name, data)
}

pub fn read_file(name: &str) -> Result<Vec<u8>, &'static str> {
    NONOS_FILESYSTEM.read_file(name)
}

pub fn write_file(name: &str, data: &[u8]) -> Result<(), &'static str> {
    NONOS_FILESYSTEM.write_file(name, data)
}

pub fn delete_file(name: &str) -> Result<(), &'static str> {
    NONOS_FILESYSTEM.delete_file(name)
}

pub fn list_files() -> Vec<String> {
    NONOS_FILESYSTEM.list_files()
}

pub fn init_nonos_fs() -> Result<(), &'static str> {
    crate::log_info!("Initializing N0N-OS RAM-only filesystem");
    match create_file("zero_state_init", b"ZeroState FS initialized (RAM-only)") {
        Ok(_) => {
            crate::log_info!("N0N-OS filesystem initialization successful");
            Ok(())
        }
        Err(e) => {
            crate::log_err!("N0N-OS filesystem initialization failed: {}", e);
            Err("Failed to initialize N0N-OS filesystem")
        }
    }
}
