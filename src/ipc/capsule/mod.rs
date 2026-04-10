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
pub mod queue;
pub mod router;
pub mod service;

pub use types::*;
pub use queue::{init_queues, create_queue, destroy_queue, enqueue, dequeue, peek, queue_len, total_pending};
pub use router::{init_router, set_route, get_route, remove_route, check_route, allow_all, deny_all};
pub use service::{init as service_init, register, unregister, send, send_data, send_request, recv, pending, connect, disconnect};
