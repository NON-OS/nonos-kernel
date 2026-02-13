// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::types::BindingInput;
#[cfg(feature = "zk-bind-manifest")]
use super::types::MAX_MANIFEST_SIZE;
/// Select binding source when manifest binding is enabled
#[cfg(feature = "zk-bind-manifest")]
pub fn select_binding<'a>(
    public_inputs: &'a [u8],
    manifest: Option<&'a [u8]>,
) -> Result<BindingInput<'a>, &'static str> {
    let m = manifest.ok_or("zk: manifest missing for binding")?;
    if m.len() > MAX_MANIFEST_SIZE {
        return Err("zk: manifest too large");
    }
    Ok(BindingInput::Manifest(m))
}
/// Select binding source when manifest binding is disabled (default)
#[cfg(not(feature = "zk-bind-manifest"))]
pub fn select_binding<'a>(
    public_inputs: &'a [u8],
    _manifest: Option<&'a [u8]>,
) -> Result<BindingInput<'a>, &'static str> {
    Ok(BindingInput::PublicInputs(public_inputs))
}

pub const fn is_manifest_binding_enabled() -> bool {
    cfg!(feature = "zk-bind-manifest")
}
