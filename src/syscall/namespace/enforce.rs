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

use super::types::NamespaceType;
use super::manager::NamespaceManager;

pub fn check_pid_visibility(viewer_pid: u64, target_pid: u64) -> bool {
    let viewer_ns = NamespaceManager::get_ns(viewer_pid, NamespaceType::Pid);
    let target_ns = NamespaceManager::get_ns(target_pid, NamespaceType::Pid);
    if viewer_ns == 0 || target_ns == 0 { return true; }
    viewer_ns == target_ns || is_ancestor_ns(viewer_ns, target_ns)
}

pub fn check_ipc_access(pid_a: u64, pid_b: u64) -> bool {
    let ns_a = NamespaceManager::get_ns(pid_a, NamespaceType::Ipc);
    let ns_b = NamespaceManager::get_ns(pid_b, NamespaceType::Ipc);
    if ns_a == 0 || ns_b == 0 { return true; }
    ns_a == ns_b
}

pub fn check_mount_access(pid: u64, mount_ns: u64) -> bool {
    let proc_ns = NamespaceManager::get_ns(pid, NamespaceType::Mount);
    if proc_ns == 0 { return true; }
    proc_ns == mount_ns
}

pub fn check_net_access(pid: u64, iface_id: u32) -> bool {
    let net_ns = NamespaceManager::get_ns(pid, NamespaceType::Net);
    if net_ns == 0 { return true; }
    super::netns::can_access_interface(net_ns, iface_id)
}

pub fn translate_pid(viewer_pid: u64, target_pid: u64) -> Option<u64> {
    if !check_pid_visibility(viewer_pid, target_pid) { return None; }
    let target_ns = NamespaceManager::get_ns(target_pid, NamespaceType::Pid);
    if target_ns == 0 { return Some(target_pid); }
    Some(target_pid)
}

fn is_ancestor_ns(ancestor: u64, descendant: u64) -> bool {
    if ancestor == descendant { return true; }
    if let Some(user_ns) = super::userns::get_user_ns(descendant) {
        if user_ns.parent_ns == ancestor { return true; }
        if user_ns.parent_ns != 0 { return is_ancestor_ns(ancestor, user_ns.parent_ns); }
    }
    false
}

pub fn check_capability_in_ns(pid: u64, ns_type: NamespaceType, cap: u64) -> bool {
    let ns_id = NamespaceManager::get_ns(pid, ns_type);
    if ns_id == 0 { return crate::security::policy::capability::has_capability(pid as u32, cap); }
    let user_ns = NamespaceManager::get_ns(pid, NamespaceType::User);
    if user_ns != 0 {
        if let Some(uns) = super::userns::get_user_ns(user_ns) {
            let mapped_uid = super::userns::map_uid_from_ns(user_ns, 0);
            if mapped_uid == Some(uns.owner_uid) { return true; }
        }
    }
    false
}

pub fn enforce_ns_isolation(pid: u64, target_pid: u64, operation: &str) -> Result<(), i32> {
    if !check_pid_visibility(pid, target_pid) {
        crate::security::monitoring::audit::log_security_event(
            "namespace", crate::security::monitoring::audit::AuditSeverity::Warning,
            alloc::format!("NS isolation: pid {} denied {} on pid {}", pid, operation, target_pid),
            Some(pid), None, None);
        return Err(-1);
    }
    Ok(())
}
