// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const MAX_KERNEL_SIZE: usize = 512 * 1024 * 1024;

#[derive(Debug)]
pub enum FileLoadError {
    NoFilesystem,
    OpenVolumeFailed,
    FileNotFound,
    OpenFailed,
    InfoFailed,
    TooLarge,
    AllocationFailed,
    ReadFailed,
    NotRegularFile,
}

pub type FileResult<T> = Result<T, FileLoadError>;
