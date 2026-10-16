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

//! A pill: a short status label on a fully rounded body, with an optional
//! status dot in front of it. The pill is drawn at its own size, at the left
//! edge of the box it is given and centred vertically in it, so an app passes
//! the box it wants the pill in. With a tone and no dot the label takes the
//! tone's colour; with a dot the dot carries the tone and the label stays in
//! `text`.

mod build;
mod geometry;
mod measure;
mod paint;

pub use build::Pill;
