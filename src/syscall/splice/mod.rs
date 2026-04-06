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
mod pipe_buffer;
mod splice;
mod tee;
mod vmsplice;
mod sync_file_range;
mod stats;

pub use types::{SpliceFlags, SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT};
pub use pipe_buffer::PipeBuffer;
pub use splice::handle_splice;
pub use tee::handle_tee;
pub use vmsplice::handle_vmsplice;
pub use sync_file_range::handle_sync_file_range;
pub use stats::{SpliceStats, get_stats, reset_stats, record_splice, record_tee, record_vmsplice};
