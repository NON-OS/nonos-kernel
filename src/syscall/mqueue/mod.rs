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
mod queue;
mod mq_open;
mod mq_unlink;
mod mq_timedsend;
mod mq_timedreceive;
mod mq_notify;
mod mq_getsetattr;
mod fd;
mod stats;
mod notify;

pub use types::{MqAttr, MqMessage, MQ_MAXMSG_DEFAULT, MQ_MSGSIZE_DEFAULT};
pub use queue::MessageQueue;
pub use mq_open::handle_mq_open;
pub use mq_unlink::handle_mq_unlink;
pub use mq_timedsend::handle_mq_timedsend;
pub use mq_timedreceive::handle_mq_timedreceive;
pub use mq_notify::handle_mq_notify;
pub use mq_getsetattr::handle_mq_getsetattr;
pub use fd::{set_fd_flags, get_fd_flags, is_nonblocking, close_mq_fd, validate_mq_fd};
pub use stats::{MqStats, get_stats, reset_stats, get_total_queues, get_total_sent};
pub use notify::{register_notification, unregister_notification, trigger_notification, MqNotification};
