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

pub mod queue;
pub mod router;
pub mod service;
pub mod types;

pub use queue::{
    create_queue, dequeue, destroy_queue, enqueue, init_queues, peek, queue_len, total_pending,
};
pub use router::{
    allow_all, check_route, deny_all, get_route, init_router, remove_route, set_route,
};
pub use service::{
    connect, disconnect, init as service_init, pending, recv, register, send, send_data,
    send_request, unregister,
};
pub use types::*;
