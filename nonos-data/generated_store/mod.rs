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

mod amazon;
mod digicert;
mod entrust;
mod globalsign;
mod google;
mod intermediates;
mod isrg;
mod others;

use super::types::TrustedRootCa;
use amazon::AMAZON_ROOTS;
use digicert::DIGICERT_ROOTS;
use entrust::ENTRUST_ROOTS;
use globalsign::GLOBALSIGN_ROOTS;
use google::GOOGLE_ROOTS;
use intermediates::{LETSENCRYPT_INTERMEDIATES, DIGICERT_INTERMEDIATES, SECTIGO_INTERMEDIATES, MICROSOFT_INTERMEDIATES};
use isrg::ISRG_ROOTS;
use others::OTHER_ROOTS;

pub static TRUSTED_ROOT_GROUPS: &[&[TrustedRootCa]] = &[
    ISRG_ROOTS,
    DIGICERT_ROOTS,
    GLOBALSIGN_ROOTS,
    OTHER_ROOTS,
    AMAZON_ROOTS,
    GOOGLE_ROOTS,
    ENTRUST_ROOTS,
    LETSENCRYPT_INTERMEDIATES,
    DIGICERT_INTERMEDIATES,
    SECTIGO_INTERMEDIATES,
    MICROSOFT_INTERMEDIATES,
];
