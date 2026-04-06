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
mod commands;
mod map;
mod program;
mod verifier;
mod syscall;
mod stats;
mod fd;

pub use types::{BpfCmd, BpfMapType, BpfProgType, BpfAttr};
pub use commands::{BpfMapCreate, BpfProgLoad};
pub use map::BpfMap;
pub use program::BpfProgram;
pub use verifier::BpfVerifier;
pub use syscall::handle_bpf;
pub use stats::{BpfStats, get_stats, reset_stats, get_programs_loaded, get_maps_created};
pub use fd::{BpfFdType, register_fd, get_fd_type, is_bpf_fd, is_program_fd, is_map_fd, close_bpf_fd};
