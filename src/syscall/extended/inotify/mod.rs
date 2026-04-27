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
    InotifyEvent, InotifyStats, IN_ACCESS, IN_ALL_EVENTS, IN_ATTRIB, IN_CLOEXEC, IN_CLOSE,
    IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_DONT_FOLLOW,
    IN_EXCL_UNLINK, IN_IGNORED, IN_ISDIR, IN_MASK_ADD, IN_MASK_CREATE, IN_MODIFY, IN_MOVE,
    IN_MOVED_FROM, IN_MOVED_TO, IN_MOVE_SELF, IN_NONBLOCK, IN_ONESHOT, IN_ONLYDIR, IN_OPEN,
    IN_Q_OVERFLOW, IN_UNMOUNT,
};

pub use syscalls::{
    handle_inotify_add_watch, handle_inotify_init, handle_inotify_init1, handle_inotify_rm_watch,
};

pub use util::{
    fd_to_inotify_id, get_inotify_stats, inotify_close, inotify_has_events, inotify_read,
    is_inotify, notify_event, notify_move,
};

pub use close::{cleanup_stale, close_all, close_all_for_process, close_if_cloexec};
pub use fd::{
    allocate_fd, fd_count, fd_to_instance_id, instance_count, is_inotify_fd, is_nonblocking,
    release_fd,
};
pub use instance::*;
pub use notify::{
    notify_access, notify_attrib, notify_close_nowrite, notify_close_write, notify_create,
    notify_delete, notify_modify, notify_open,
};
pub use queue::{
    clear_events, has_pending_events, peek_event, pending_events, queue_event, queue_remaining,
    total_queued_events,
};
pub use read::{
    bytes_available, can_read, inotify_read_to_buffer, peek_next_event_size, read_single_event,
};
pub use watch::{
    add_watch, all_watches, find_watch_by_path, get_watch_mask, get_watch_path, remove_watch,
    total_watches, watch_count,
};
