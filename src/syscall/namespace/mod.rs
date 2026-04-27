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

mod clone;
pub mod enforce;
mod fd;
mod manager;
pub mod netns;
mod setns;
mod stats;
mod types;
mod unshare;
pub mod userns;

pub use clone::{
    cleanup_process_namespaces, clone_namespaces_for_fork, get_all_namespaces, share_namespace,
};
pub use enforce::{
    check_ipc_access, check_mount_access, check_net_access, check_pid_visibility,
    enforce_ns_isolation,
};
pub use fd::*;
pub use manager::{NamespaceManager, ProcessNamespaces};
pub use netns::{
    add_interface, create_net_ns, create_veth_pair, remove_interface, NetNamespace, NetRoute,
};
pub use setns::handle_setns;
pub use stats::*;
pub use types::*;
pub use unshare::handle_unshare;
pub use userns::{
    create_user_ns, map_uid_from_ns, map_uid_to_ns, set_gid_map, set_uid_map, IdMapping,
    UserNamespace,
};
