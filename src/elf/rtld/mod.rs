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

pub mod entry;
pub mod init;
pub mod load;
pub mod search;
pub mod resolve;
pub mod relocate;
pub mod tls;
pub mod lazy;
pub mod audit;
pub mod preload;
pub mod debug;

pub use entry::{rtld_start, rtld_entry, RtldState};
pub use init::{rtld_init, rtld_setup, RtldConfig};
pub use load::{load_library, load_needed, LoadedObject, ObjectList};
pub use search::{search_library, LibrarySearchPath, add_search_path, get_search_paths};
pub use resolve::{resolve_symbol, resolve_plt, SymbolResolution};
pub use relocate::{process_relocs, apply_relocation, RelocationContext};
pub use tls::{init_tls, allocate_tls_block, TlsDescriptor, TlsModule};
pub use lazy::{lazy_bind, plt_resolver, LazyBindingState};
pub use audit::{AuditInterface, AuditEvent, register_audit};
pub use preload::{parse_preload, load_preloaded, PreloadList};
pub use debug::{RDebug, RDebugState, update_debug_state, get_r_debug};
