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

mod types;
mod context;
mod io_setup;
mod io_destroy;
mod io_submit;
mod io_getevents;
mod io_cancel;
mod stats;
mod fd;

pub use types::{Iocb, IoEvent, AioOpcode, MAX_AIO_EVENTS, IOCB_FLAG_RESFD, IOCB_FLAG_IOPRIO};
pub use context::AioContext;
pub use io_setup::handle_io_setup;
pub use io_destroy::handle_io_destroy;
pub use io_submit::handle_io_submit;
pub use io_getevents::handle_io_getevents;
pub use io_cancel::{handle_io_cancel, cancel_all_for_context, cancel_by_fd, is_cancellable};
pub use stats::{AioStats, get_stats, reset_stats, get_total_contexts, get_total_submitted};
pub use fd::{allocate_aio_fd, lookup_context_by_fd, release_aio_fd, is_aio_fd, cleanup_fds_for_context};
