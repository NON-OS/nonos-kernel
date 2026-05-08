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

mod ack_irq;
mod drain_events;
mod halt;
mod issue_noop_and_wait;
mod layout;
mod program_command_ring;
mod program_dcbaa;
mod program_event_ring;
mod refuse_unsupported;
mod reset;
mod ring_doorbell;
mod scratchpad;
mod start;
mod wait_cnr_clear;
mod wait_hc_running;

pub use ack_irq::ack_irq;
pub use drain_events::drain_events;
pub use halt::halt;
pub use issue_noop_and_wait::issue_noop_and_wait;
pub use layout::ControllerLayout;
pub use program_command_ring::program_command_ring;
pub use program_dcbaa::program_dcbaa;
pub use program_event_ring::program_event_ring;
pub use refuse_unsupported::refuse_unsupported;
pub use reset::reset;
pub use scratchpad::Scratchpads;
pub use start::start;
pub use wait_cnr_clear::wait_cnr_clear;
pub use wait_hc_running::wait_hc_running;
