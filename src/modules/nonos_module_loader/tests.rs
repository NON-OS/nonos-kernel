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


#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use crate::modules::nonos_module_loader::{
        get_module_info, load_module, unload_module, NonosModuleType,
    };

    #[test]
    fn test_module_load_and_erase() {
        let code = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let sig = [0u8; 64];
        let id = load_module("test", NonosModuleType::System, code.clone(), &sig).unwrap();
        assert_eq!(get_module_info(id).unwrap().name, "test");
        unload_module(id).unwrap();
        assert!(get_module_info(id).is_err());
    }

    #[test]
    fn test_module_lifecycle() {
        use crate::modules::nonos_module_loader::{start_module, stop_module, NonosModuleState};

        let code = vec![0u8; 16];
        let sig = [0u8; 64];
        let id = load_module("lifecycle_test", NonosModuleType::Application, code, &sig).unwrap();

        let info = get_module_info(id).unwrap();
        assert_eq!(info.state, NonosModuleState::Loaded);

        start_module(id).unwrap();
        let info = get_module_info(id).unwrap();
        assert_eq!(info.state, NonosModuleState::Running);

        stop_module(id).unwrap();
        let info = get_module_info(id).unwrap();
        assert_eq!(info.state, NonosModuleState::Stopped);

        unload_module(id).unwrap();
    }

    #[test]
    fn test_module_types() {
        let code = vec![0u8; 8];
        let sig = [0u8; 64];

        let sys_id = load_module("sys", NonosModuleType::System, code.clone(), &sig).unwrap();
        let app_id = load_module("app", NonosModuleType::Application, code.clone(), &sig).unwrap();
        let drv_id = load_module("drv", NonosModuleType::Driver, code.clone(), &sig).unwrap();
        let svc_id = load_module("svc", NonosModuleType::Service, code.clone(), &sig).unwrap();

        assert_eq!(get_module_info(sys_id).unwrap().module_type, NonosModuleType::System);
        assert_eq!(get_module_info(app_id).unwrap().module_type, NonosModuleType::Application);
        assert_eq!(get_module_info(drv_id).unwrap().module_type, NonosModuleType::Driver);
        assert_eq!(get_module_info(svc_id).unwrap().module_type, NonosModuleType::Service);

        unload_module(sys_id).unwrap();
        unload_module(app_id).unwrap();
        unload_module(drv_id).unwrap();
        unload_module(svc_id).unwrap();
    }
}
