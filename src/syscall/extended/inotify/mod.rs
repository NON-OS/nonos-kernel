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
pub mod fd;
pub mod instance;
pub mod notify;
pub mod queue;
pub mod read;
pub mod syscalls;
pub mod types;
pub mod util;
pub mod watch;

pub use types::{
    IN_CLOEXEC, IN_NONBLOCK,
    IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE, IN_CLOSE_NOWRITE,
    IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE,
    IN_DELETE_SELF, IN_MOVE_SELF, IN_CLOSE, IN_MOVE, IN_ALL_EVENTS,
    IN_ONLYDIR, IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_MASK_CREATE,
    IN_MASK_ADD, IN_ISDIR, IN_ONESHOT, IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED,
    InotifyEvent, InotifyStats,
};

pub use syscalls::{
    handle_inotify_init, handle_inotify_init1,
    handle_inotify_add_watch, handle_inotify_rm_watch,
};

pub use util::{
    inotify_read, inotify_close, notify_event, notify_move,
    inotify_has_events, is_inotify, fd_to_inotify_id, get_inotify_stats,
};

pub use close::{close_all_for_process, close_if_cloexec, cleanup_stale, close_all};
pub use fd::{allocate_fd, release_fd, fd_to_instance_id, is_inotify_fd, fd_count, instance_count, is_nonblocking};
pub use notify::{notify_access, notify_modify, notify_attrib, notify_open, notify_create, notify_delete, notify_close_write, notify_close_nowrite};
pub use queue::{queue_event, pending_events, has_pending_events, clear_events, peek_event, queue_remaining, total_queued_events};
pub use read::{inotify_read_to_buffer, can_read, bytes_available, read_single_event, peek_next_event_size};
pub use watch::{add_watch, remove_watch, get_watch_path, get_watch_mask, watch_count, all_watches, find_watch_by_path, total_watches};
