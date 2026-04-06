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

mod superblock;
mod group_desc;
mod inode;
mod extent;
mod dir;
mod file;
mod balloc;
mod ialloc;
mod namei;
mod xattr;
mod journal;
mod mount;
mod read;
mod write;

pub use superblock::{Ext4Superblock, read_superblock, write_superblock};
pub use group_desc::{Ext4GroupDesc, read_group_desc, write_group_desc};
pub use inode::{Ext4Inode, read_inode, write_inode, EXT4_ROOT_INO};
pub use extent::{Ext4Extent, Ext4ExtentHeader, extent_lookup, extent_insert};
pub use dir::{Ext4DirEntry, dir_lookup, dir_add_entry, dir_remove_entry, dir_iterate};
pub use file::{ext4_open, ext4_close, ext4_read, ext4_write, ext4_truncate};
pub use balloc::{alloc_block, free_block, alloc_blocks};
pub use ialloc::{alloc_inode, free_inode};
pub use namei::{ext4_lookup, ext4_create, ext4_mkdir, ext4_unlink, ext4_rmdir};
pub use xattr::{ext4_getxattr, ext4_setxattr, ext4_listxattr, ext4_removexattr};
pub use journal::{Ext4Journal, journal_start, journal_stop, journal_commit};
pub use mount::{ext4_mount, ext4_unmount, ext4_sync, Ext4MountInfo};
