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

mod error;
mod types;
mod filesystem;

pub use error::{FsError, FsResult};
pub use types::{
    DirEntry, FsStatistics, NonosFile, NonosFileInfo, NonosFileSystemType,
    KEY_SIZE, MAX_FILE_SIZE, MAX_FILES, MAX_PATH_LEN, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
    secure_zeroize, secure_zeroize_array,
};
pub use filesystem::{
    create_dir, create_file, delete, delete_file, dir_exists, exists, file_exists,
    get_filesystem, init_nonos_fs, init_nonos_filesystem, list_dir, list_dir_entries,
    list_files, normalize_path, read_file, rename, stats, write_file,
    NonosFilesystem, NONOS_FILESYSTEM,
};
