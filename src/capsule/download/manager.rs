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

extern crate alloc;
use alloc::vec::Vec;
use crate::network::ipfs;
use crate::capsule::{self, CapsuleId, UnlockToken};
use super::{cache, progress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadError { FetchFailed, VerifyFailed, LoadFailed, Cached, NotFound }

pub fn download_and_load(cid: &str, token: UnlockToken) -> Result<CapsuleId, DownloadError> {
    progress::set_status(cid, progress::Status::Downloading);
    if let Some(data) = cache::get(cid) {
        progress::set_status(cid, progress::Status::Cached);
        return load_capsule(&data, token);
    }
    let data = ipfs::fetch_capsule(cid).map_err(|_| DownloadError::FetchFailed)?;
    progress::set_status(cid, progress::Status::Verifying);
    verify_capsule(&data)?;
    progress::set_status(cid, progress::Status::Loading);
    let id = load_capsule(&data, token)?;
    cache::insert(cid, data);
    progress::set_status(cid, progress::Status::Complete);
    Ok(id)
}

pub fn download_only(cid: &str) -> Result<Vec<u8>, DownloadError> {
    if let Some(data) = cache::get(cid) { return Ok(data); }
    let data = ipfs::fetch_capsule(cid).map_err(|_| DownloadError::FetchFailed)?;
    verify_capsule(&data)?;
    cache::insert(cid, data.clone());
    Ok(data)
}

fn verify_capsule(data: &[u8]) -> Result<(), DownloadError> {
    if data.len() < 64 { return Err(DownloadError::VerifyFailed); }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != capsule::NOXC_MAGIC { return Err(DownloadError::VerifyFailed); }
    Ok(())
}

fn load_capsule(data: &[u8], token: UnlockToken) -> Result<CapsuleId, DownloadError> {
    capsule::load(data, token).map_err(|_| DownloadError::LoadFailed)
}

pub fn prefetch(cid: &str) -> Result<(), DownloadError> {
    download_only(cid)?;
    Ok(())
}
