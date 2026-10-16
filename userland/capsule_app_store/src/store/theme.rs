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
//! The tones the store's own words carry: `Progress::sentence` names one
//! with each line, and the painter gives it a role from
//! `nonos_toolkit::theme::roles()`. No colour lives here, so the proofs that
//! mount this file and read those words need no toolkit.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Muted,
    Accent,
    Ok,
    Danger,
}

pub use Tone::{Accent as ACCENT, Danger as DANGER, Muted as MUTED, Ok as OK};
