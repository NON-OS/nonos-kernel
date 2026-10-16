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

//! The table of roles, one field per colour a widget may ask for.

use super::super::colour::{Opaque, Translucent};

/// The colours a widget draws with, worked out from the theme in force. What each
/// one means is in docs/userland/design-system/colours.md.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Roles {
    pub bg: Opaque,
    pub sunken: Opaque,
    pub surface: Opaque,
    pub inset: Opaque,
    pub raised: Opaque,
    pub border: Opaque,
    pub border_soft: Opaque,
    pub border_strong: Opaque,
    pub text: Opaque,
    pub text_2: Opaque,
    pub muted: Opaque,
    pub quiet: Opaque,
    pub disabled: Opaque,
    pub accent: Opaque,
    pub accent_text: Opaque,
    pub on_accent: Opaque,
    pub accent_wash: Translucent,
    pub accent_edge: Translucent,
    pub focus_ring: Translucent,
    pub hover_wash: Translucent,
    pub ok: Opaque,
    pub warn: Opaque,
    pub danger: Opaque,
    pub warn_soft: Opaque,
    pub shadow: Translucent,
    pub scrim: Translucent,
}
