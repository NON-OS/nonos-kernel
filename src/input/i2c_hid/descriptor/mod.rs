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

mod field_location;
mod hid_descriptor;
mod layout_types;
mod parse;
mod parse_context;
mod parse_global;
mod parse_local;
mod parse_main;
mod record_field;
mod report_types;

pub use field_location::FieldLocation;
pub use hid_descriptor::HidDescriptor;
pub use layout_types::{ContactFields, ReportInfo, TouchpadLayout};
pub use report_types::ReportDescriptor;
