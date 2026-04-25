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

pub mod instance;
pub mod stats;
pub mod syscalls;
pub mod types;
pub mod util;

pub use types::{
    SignalfdInfo, SignalfdSiginfo, SignalfdStats, SFD_CLOEXEC, SFD_NONBLOCK, SIGNALFD_SIGINFO_SIZE,
};

pub use syscalls::{handle_signalfd, handle_signalfd4};

pub use util::{
    cleanup_process_signalfds, fd_to_signalfd_id, get_signalfd_info, get_signalfd_stats,
    is_signalfd, route_signal_to_signalfd, signalfd_close, signalfd_count, signalfd_has_pending,
    signalfd_read,
};

pub use stats::{get_global_stats, reset_stats as reset_global_stats, SignalfdGlobalStats};
