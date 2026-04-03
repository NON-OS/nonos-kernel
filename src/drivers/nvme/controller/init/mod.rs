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

mod capabilities;
mod enable;
mod configure;
mod doorbell;
mod shutdown;

pub use capabilities::{read_capabilities, read_version};
pub use enable::{disable_controller, enable_controller};
pub use configure::{configure_admin_queue, configure_msix, unmask_interrupts};
pub use doorbell::{get_doorbell_stride, calculate_sq_doorbell, calculate_cq_doorbell};
pub use shutdown::{shutdown_controller, subsystem_reset};
