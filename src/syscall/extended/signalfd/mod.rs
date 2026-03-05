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

pub mod types;
pub mod instance;
pub mod syscalls;
pub mod util;

pub use types::{
    SFD_CLOEXEC, SFD_NONBLOCK, SIGNALFD_SIGINFO_SIZE,
    SignalfdSiginfo, SignalfdInfo, SignalfdStats,
};

pub use syscalls::{handle_signalfd, handle_signalfd4};

pub use util::{
    signalfd_read, signalfd_close, route_signal_to_signalfd,
    get_signalfd_info, signalfd_has_pending, fd_to_signalfd_id,
    is_signalfd, signalfd_count, get_signalfd_stats, cleanup_process_signalfds,
};
