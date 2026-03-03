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

mod features;
mod identify;
mod logs;
mod queue_ops;

pub use features::{abort_command, get_feature, get_number_of_queues, set_feature, set_number_of_queues};
pub use identify::{get_active_namespace_list, identify_controller, identify_namespace};
pub use logs::{format_nvm, get_log_page, get_smart_log, SmartLog};
pub use queue_ops::{
    create_io_completion_queue, create_io_submission_queue, delete_io_completion_queue,
    delete_io_submission_queue,
};
