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

use super::wakeup::signal_completion;
use crate::drivers::nvme::controller::NvmeController;
use crate::drivers::nvme::driver::get_controller;
use crate::drivers::nvme::queue::IoQueue;
use x86_64::structures::idt::InterruptStackFrame;

pub fn nvme_isr(_frame: InterruptStackFrame) {
    if let Some(ctrl) = get_controller() {
        process_all_queues(ctrl);
    }
}

fn process_all_queues(ctrl: &NvmeController) {
    let io_queues = ctrl.io_queues_ref();
    for (idx, q) in io_queues.iter().enumerate() {
        process_completions(q, (idx + 1) as u16);
    }
}

pub fn process_completions(queue: &IoQueue, queue_id: u16) {
    while let Some(entry) = queue.try_poll_completion() {
        signal_completion(queue_id, entry.cid);
    }
}
