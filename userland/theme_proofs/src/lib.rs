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

//! Host proofs for the live theme.

/// The text size table, included from the toolkit so the proofs measure the
/// factors the desktop actually draws with.
#[path = "../../toolkit/src/font/ttf/text_scale.rs"]
pub mod text_scale;

pub mod theme;

/// The toolkit service's wire: the header decode every frame passes and the
/// refusal a frame it cannot decode is answered with.
#[path = "../../toolkit/src/protocol/mod.rs"]
pub mod protocol;

/// What the service's OP_COMPONENT_RENDER paints with, at the `crate::` paths
/// the toolkit's component files name: the bitmap font, colour, and the
/// panel, button and label painters. The toolkit's own lint choice (painters
/// take a buffer and its geometry as plain arguments) is allowed on the
/// include rather than restyled.
#[allow(clippy::too_many_arguments)]
#[path = "toolkit_components.rs"]
pub mod components;
#[path = "toolkit_design.rs"]
pub mod design;
#[allow(clippy::too_many_arguments)]
#[path = "toolkit_font.rs"]
pub mod font;

#[cfg(test)]
mod wcag;

#[cfg(test)]
mod contrast_edge_tests;
#[cfg(test)]
mod contrast_tests;
#[cfg(test)]
mod derive_alpha_tests;
#[cfg(test)]
mod derive_tests;
#[cfg(test)]
mod roles_alpha_tests;
#[cfg(test)]
mod roles_tests;
#[cfg(test)]
mod scheme_accent_tests;
#[cfg(test)]
mod scheme_contrast_tests;
#[cfg(test)]
mod scheme_tests;
#[cfg(test)]
mod text_scale_range_tests;
#[cfg(test)]
mod text_scale_tests;
#[cfg(test)]
mod toolkit_paint_tests;
#[cfg(test)]
mod toolkit_refusal_tests;
#[cfg(test)]
mod widget_tests;
