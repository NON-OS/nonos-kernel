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

mod array;
mod date;
mod number;
mod object;
mod regexp;
mod string;

pub use array::create_array_prototype;
pub use date::create_date_constructor;
pub use number::create_number_constructor;
pub use object::create_object_constructor;
pub use regexp::create_regexp_constructor;
pub use string::create_string_prototype;
