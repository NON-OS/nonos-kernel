// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use alloc::string::String;
use alloc::vec::Vec;

pub const MAX_FILES: usize = 256;
pub const MAX_OPEN_FDS: usize = 256;
pub const MAX_FILE_BYTES: usize = 1 << 20; // 1 MiB per file in this slice

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    AlreadyExists,
    BadFd,
    Full,
    InvalidArgument,
    AccessDenied,
}

pub type StoreResult<T> = Result<T, StoreError>;

struct File {
    name: String,
    data: Vec<u8>,
}

struct OpenFd {
    file_idx: usize,
    owner_pid: u32,
    pos: usize,
    append: bool,
    writable: bool,
}

pub struct Store {
    files: Vec<File>,
    fds: Vec<Option<OpenFd>>,
}

impl Store {
    pub fn new() -> Self {
        let mut fds = Vec::with_capacity(MAX_OPEN_FDS);
        for _ in 0..MAX_OPEN_FDS {
            fds.push(None);
        }
        Self { files: Vec::new(), fds }
    }

    pub fn open(
        &mut self,
        path: &str,
        owner_pid: u32,
        create: bool,
        truncate: bool,
        append: bool,
    ) -> StoreResult<u32> {
        let mut idx = self.find(path);
        if idx.is_none() {
            if !create {
                return Err(StoreError::NotFound);
            }
            if self.files.len() >= MAX_FILES {
                return Err(StoreError::Full);
            }
            self.files.push(File { name: String::from(path), data: Vec::new() });
            idx = Some(self.files.len() - 1);
        }
        let i = idx.unwrap();
        if truncate {
            self.files[i].data.clear();
        }
        let fd_slot = match self.fds.iter().position(|s| s.is_none()) {
            Some(s) => s,
            None => return Err(StoreError::Full),
        };
        let pos = if append { self.files[i].data.len() } else { 0 };
        self.fds[fd_slot] =
            Some(OpenFd { file_idx: i, owner_pid, pos, append, writable: true });
        Ok(fd_slot as u32)
    }

    pub fn close(&mut self, fd: u32, owner_pid: u32) -> StoreResult<()> {
        let slot = self.slot_mut(fd, owner_pid)?;
        *slot = None;
        Ok(())
    }

    pub fn read(&mut self, fd: u32, owner_pid: u32, max: usize) -> StoreResult<Vec<u8>> {
        let (file_idx, pos) = {
            let entry = self.entry(fd, owner_pid)?;
            (entry.file_idx, entry.pos)
        };
        let data = &self.files[file_idx].data;
        let avail = data.len().saturating_sub(pos);
        let n = if max < avail { max } else { avail };
        let out = data[pos..pos + n].to_vec();
        if let Some(entry) = self.fds[fd as usize].as_mut() {
            entry.pos = pos + n;
        }
        Ok(out)
    }

    pub fn write(&mut self, fd: u32, owner_pid: u32, bytes: &[u8]) -> StoreResult<u32> {
        let (file_idx, append, pos, writable) = {
            let entry = self.entry(fd, owner_pid)?;
            (entry.file_idx, entry.append, entry.pos, entry.writable)
        };
        if !writable {
            return Err(StoreError::AccessDenied);
        }
        let data = &mut self.files[file_idx].data;
        let start = if append { data.len() } else { pos };
        let end = start.saturating_add(bytes.len());
        if end > MAX_FILE_BYTES {
            return Err(StoreError::Full);
        }
        if end > data.len() {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(bytes);
        if let Some(entry) = self.fds[fd as usize].as_mut() {
            entry.pos = end;
        }
        Ok(bytes.len() as u32)
    }

    pub fn stat(&self, path: &str) -> StoreResult<u64> {
        match self.find(path) {
            Some(i) => Ok(self.files[i].data.len() as u64),
            None => Err(StoreError::NotFound),
        }
    }

    pub fn list(&self, prefix: &str, max_bytes: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for f in self.files.iter() {
            if !f.name.starts_with(prefix) {
                continue;
            }
            let nb = f.name.as_bytes();
            if nb.len() > 255 {
                continue;
            }
            if out.len() + 1 + nb.len() > max_bytes {
                break;
            }
            out.push(nb.len() as u8);
            out.extend_from_slice(nb);
        }
        out
    }

    fn find(&self, path: &str) -> Option<usize> {
        self.files.iter().position(|f| f.name == path)
    }

    fn entry(&self, fd: u32, owner_pid: u32) -> StoreResult<&OpenFd> {
        let idx = fd as usize;
        if idx >= self.fds.len() {
            return Err(StoreError::BadFd);
        }
        match self.fds[idx].as_ref() {
            Some(e) if e.owner_pid == owner_pid => Ok(e),
            Some(_) => Err(StoreError::BadFd),
            None => Err(StoreError::BadFd),
        }
    }

    fn slot_mut(&mut self, fd: u32, owner_pid: u32) -> StoreResult<&mut Option<OpenFd>> {
        let idx = fd as usize;
        if idx >= self.fds.len() {
            return Err(StoreError::BadFd);
        }
        match self.fds[idx].as_ref() {
            Some(e) if e.owner_pid == owner_pid => Ok(&mut self.fds[idx]),
            Some(_) => Err(StoreError::BadFd),
            None => Err(StoreError::BadFd),
        }
    }
}
