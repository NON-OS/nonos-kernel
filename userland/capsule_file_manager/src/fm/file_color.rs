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

use nonos_toolkit::theme::roles;

use super::filetype::Kind;

/// The filetype tint, a categorical scale over theme roles: folders in the
/// accent, code in its lighter accent text, images in ok, archives in warn,
/// executables in danger, documents in text and anything else muted.
pub fn color(kind: Kind) -> u32 {
    let r = roles();
    let ink = match kind {
        Kind::Dir => r.accent,
        Kind::Code => r.accent_text,
        Kind::Image => r.ok,
        Kind::Doc => r.text,
        Kind::Archive => r.warn,
        Kind::Exec => r.danger,
        Kind::Other => r.muted,
    };
    ink.argb()
}
