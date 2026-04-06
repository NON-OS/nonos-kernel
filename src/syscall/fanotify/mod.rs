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

pub mod close;
pub mod event;
pub mod fd;
pub mod init;
pub mod mark;
pub mod notify;
pub mod queue;
pub mod read;
pub mod stats;
pub mod types;
pub mod util;

pub use close::{fanotify_close, close_all_for_process, close_if_cloexec, cleanup_stale, close_all};
pub use event::{FanotifyEvent, FanotifyEventMetadata, read_events};
pub use fd::{allocate_fd, release_fd, fd_to_instance, is_fanotify_fd, get_instance_id, validate_fd, is_nonblocking, is_cloexec};
pub use init::{sys_fanotify_init, FanotifyInstance, get_by_fd};
pub use mark::{sys_fanotify_mark, FanotifyMark};
pub use notify::{notify_access, notify_modify, notify_open, notify_close_write, notify_close_nowrite, notify_create, notify_delete, notify_event};
pub use queue::{queue_event, has_pending_events, pending_events, clear_events, peek_event, pop_event, queue_capacity, drain_events};
pub use read::{fanotify_read, fanotify_read_to_buffer, read_single_event, can_read, bytes_available};
pub use stats::{get_stats, instance_stats, total_instances, total_fds, total_marks, total_events, memory_usage, FanotifyStats, InstanceStats};
pub use types::FanotifyFlags;
pub use util::{is_fanotify, fd_to_fanotify_id, fanotify_has_events, notify_fs_event, get_fanotify_stats};

pub const FAN_CLOEXEC: u32 = 0x0000_0001;
pub const FAN_NONBLOCK: u32 = 0x0000_0002;
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
pub const FAN_ENABLE_AUDIT: u32 = 0x0000_0040;
pub const FAN_REPORT_TID: u32 = 0x0000_0100;
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;

pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;
pub const FAN_MARK_INODE: u32 = 0x0000_0000;
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

pub const FAN_ACCESS: u64 = 0x0000_0001;
pub const FAN_MODIFY: u64 = 0x0000_0002;
pub const FAN_ATTRIB: u64 = 0x0000_0004;
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
pub const FAN_OPEN: u64 = 0x0000_0020;
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
pub const FAN_CREATE: u64 = 0x0000_0100;
pub const FAN_DELETE: u64 = 0x0000_0200;
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
pub const FAN_ONDIR: u64 = 0x4000_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
pub const FAN_MOVE: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;
