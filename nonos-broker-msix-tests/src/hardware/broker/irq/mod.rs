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

#[path = "../../../../../src/hardware/broker/irq/types.rs"]
pub mod types;

#[path = "../../../../../src/hardware/broker/irq/validate.rs"]
pub mod validate;

#[path = "../../../../../src/hardware/broker/irq/slots.rs"]
pub mod slots;

#[path = "../../../../../src/hardware/broker/irq/records.rs"]
pub mod records;

pub mod msix_ops;

#[path = "../../../../../src/hardware/broker/irq/bind.rs"]
pub mod bind;

#[path = "../../../../../src/hardware/broker/irq/release.rs"]
pub mod release;
