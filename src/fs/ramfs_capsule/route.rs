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

pub fn is_capsule_path(path: &str) -> bool {
    path == "/ram" || path.starts_with("/ram/")
}

#[cfg(test)]
mod tests {
    use super::is_capsule_path;

    #[test]
    fn ram_root_routes() {
        assert!(is_capsule_path("/ram"));
    }

    #[test]
    fn ram_subpath_routes() {
        assert!(is_capsule_path("/ram/test"));
        assert!(is_capsule_path("/ram/a/b/c"));
    }

    #[test]
    fn non_ram_does_not_route() {
        assert!(!is_capsule_path("/ramdisk"));
        assert!(!is_capsule_path("/home/ram"));
        assert!(!is_capsule_path("/ram2"));
        assert!(!is_capsule_path("ram/foo"));
        assert!(!is_capsule_path("/disk/ram"));
        assert!(!is_capsule_path(""));
        assert!(!is_capsule_path("/"));
    }
}
