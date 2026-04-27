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

mod detect;
pub mod detect_extended;
pub mod detect_leaf1;
pub mod detect_leaf7;
mod lookup;
mod types;
mod types_new;
mod types_struct;

pub use detect_extended::{detect_extended_ecx, detect_extended_edx};
pub use detect_leaf1::{detect_leaf1_ecx, detect_leaf1_edx};
pub use detect_leaf7::{detect_leaf7_ebx, detect_leaf7_ecx, detect_leaf7_edx};
pub use lookup::has_feature;
pub use types::CpuFeatures;
