use crate::elf::types::{sym_bind, sym_type, Symbol, SymbolEntry};
use core::mem;

#[test]
fn test_symbol_size() {
    assert_eq!(mem::size_of::<Symbol>(), Symbol::SIZE);
    assert_eq!(Symbol::SIZE, 24);
}

#[test]
fn test_symbol_entry_alias() {
    assert_eq!(mem::size_of::<SymbolEntry>(), Symbol::SIZE);
}

#[test]
fn test_symbol_default() {
    let sym = Symbol::default();
    assert_eq!(sym.st_name, 0);
    assert_eq!(sym.st_info, 0);
    assert_eq!(sym.st_other, 0);
    assert_eq!(sym.st_shndx, 0);
    assert_eq!(sym.st_value, 0);
    assert_eq!(sym.st_size, 0);
}

#[test]
fn test_binding_local() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    assert_eq!(sym.binding(), sym_bind::STB_LOCAL);
}

#[test]
fn test_binding_global() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    assert_eq!(sym.binding(), sym_bind::STB_GLOBAL);
}

#[test]
fn test_binding_weak() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    assert_eq!(sym.binding(), sym_bind::STB_WEAK);
}

#[test]
fn test_binding_with_type() {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    assert_eq!(sym.binding(), sym_bind::STB_GLOBAL);
}

#[test]
fn test_sym_type_notype() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_NOTYPE;
    assert_eq!(sym.sym_type(), sym_type::STT_NOTYPE);
}

#[test]
fn test_sym_type_object() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_OBJECT;
    assert_eq!(sym.sym_type(), sym_type::STT_OBJECT);
}

#[test]
fn test_sym_type_func() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FUNC;
    assert_eq!(sym.sym_type(), sym_type::STT_FUNC);
}

#[test]
fn test_sym_type_section() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_SECTION;
    assert_eq!(sym.sym_type(), sym_type::STT_SECTION);
}

#[test]
fn test_sym_type_file() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FILE;
    assert_eq!(sym.sym_type(), sym_type::STT_FILE);
}

#[test]
fn test_sym_type_tls() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_TLS;
    assert_eq!(sym.sym_type(), sym_type::STT_TLS);
}

#[test]
fn test_sym_type_with_binding() {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    assert_eq!(sym.sym_type(), sym_type::STT_FUNC);
}

#[test]
fn test_is_local_true() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    assert!(sym.is_local());
}

#[test]
fn test_is_local_false_global() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    assert!(!sym.is_local());
}

#[test]
fn test_is_local_false_weak() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    assert!(!sym.is_local());
}

#[test]
fn test_is_global_true() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    assert!(sym.is_global());
}

#[test]
fn test_is_global_false_local() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    assert!(!sym.is_global());
}

#[test]
fn test_is_global_false_weak() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    assert!(!sym.is_global());
}

#[test]
fn test_is_weak_true() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    assert!(sym.is_weak());
}

#[test]
fn test_is_weak_false_local() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    assert!(!sym.is_weak());
}

#[test]
fn test_is_weak_false_global() {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    assert!(!sym.is_weak());
}

#[test]
fn test_is_function_true() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FUNC;
    assert!(sym.is_function());
}

#[test]
fn test_is_function_false_object() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_OBJECT;
    assert!(!sym.is_function());
}

#[test]
fn test_is_function_false_notype() {
    let sym = Symbol::default();
    assert!(!sym.is_function());
}

#[test]
fn test_is_function_with_binding() {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    assert!(sym.is_function());
}

#[test]
fn test_is_object_true() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_OBJECT;
    assert!(sym.is_object());
}

#[test]
fn test_is_object_false_func() {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FUNC;
    assert!(!sym.is_object());
}

#[test]
fn test_is_object_false_notype() {
    let sym = Symbol::default();
    assert!(!sym.is_object());
}

#[test]
fn test_is_object_with_binding() {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_OBJECT;
    assert!(sym.is_object());
}

#[test]
fn test_is_undefined_true() {
    let sym = Symbol::default();
    assert!(sym.is_undefined());
}

#[test]
fn test_is_undefined_false() {
    let mut sym = Symbol::default();
    sym.st_shndx = 1;
    assert!(!sym.is_undefined());
}

#[test]
fn test_is_undefined_false_shndx_max() {
    let mut sym = Symbol::default();
    sym.st_shndx = 0xFFFF;
    assert!(!sym.is_undefined());
}

#[test]
fn test_symbol_clone() {
    let mut sym = Symbol::default();
    sym.st_value = 0x401000;
    sym.st_size = 100;
    let cloned = sym;
    assert_eq!(cloned.st_value, 0x401000);
    assert_eq!(cloned.st_size, 100);
}

#[test]
fn test_symbol_copy() {
    let mut sym = Symbol::default();
    sym.st_name = 42;
    let copied: Symbol = sym;
    assert_eq!(copied.st_name, 42);
    assert_eq!(sym.st_name, 42);
}

#[test]
fn test_symbol_alignment() {
    assert_eq!(mem::align_of::<Symbol>(), 8);
}

#[test]
fn test_sym_bind_constants() {
    assert_eq!(sym_bind::STB_LOCAL, 0);
    assert_eq!(sym_bind::STB_GLOBAL, 1);
    assert_eq!(sym_bind::STB_WEAK, 2);
}

#[test]
fn test_sym_type_constants() {
    assert_eq!(sym_type::STT_NOTYPE, 0);
    assert_eq!(sym_type::STT_OBJECT, 1);
    assert_eq!(sym_type::STT_FUNC, 2);
    assert_eq!(sym_type::STT_SECTION, 3);
    assert_eq!(sym_type::STT_FILE, 4);
    assert_eq!(sym_type::STT_TLS, 6);
}

#[test]
fn test_symbol_global_function() {
    let mut sym = Symbol::default();
    sym.st_name = 10;
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    sym.st_shndx = 1;
    sym.st_value = 0x401000;
    sym.st_size = 256;

    assert!(sym.is_global());
    assert!(!sym.is_local());
    assert!(!sym.is_weak());
    assert!(sym.is_function());
    assert!(!sym.is_object());
    assert!(!sym.is_undefined());
    assert_eq!(sym.binding(), sym_bind::STB_GLOBAL);
    assert_eq!(sym.sym_type(), sym_type::STT_FUNC);
}

#[test]
fn test_symbol_weak_object() {
    let mut sym = Symbol::default();
    sym.st_name = 20;
    sym.st_info = (sym_bind::STB_WEAK << 4) | sym_type::STT_OBJECT;
    sym.st_shndx = 2;
    sym.st_value = 0x600000;
    sym.st_size = 8;

    assert!(!sym.is_global());
    assert!(!sym.is_local());
    assert!(sym.is_weak());
    assert!(!sym.is_function());
    assert!(sym.is_object());
    assert!(!sym.is_undefined());
    assert_eq!(sym.binding(), sym_bind::STB_WEAK);
    assert_eq!(sym.sym_type(), sym_type::STT_OBJECT);
}

#[test]
fn test_symbol_local_section() {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_LOCAL << 4) | sym_type::STT_SECTION;
    sym.st_shndx = 5;
    sym.st_value = 0x400000;

    assert!(sym.is_local());
    assert!(!sym.is_global());
    assert!(!sym.is_weak());
    assert!(!sym.is_function());
    assert!(!sym.is_object());
    assert!(!sym.is_undefined());
    assert_eq!(sym.sym_type(), sym_type::STT_SECTION);
}

#[test]
fn test_symbol_undefined_import() {
    let mut sym = Symbol::default();
    sym.st_name = 50;
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    sym.st_shndx = 0;
    sym.st_value = 0;
    sym.st_size = 0;

    assert!(sym.is_global());
    assert!(sym.is_function());
    assert!(sym.is_undefined());
}

#[test]
fn test_symbol_tls_variable() {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_TLS;
    sym.st_shndx = 7;
    sym.st_value = 0;
    sym.st_size = 4;

    assert!(sym.is_global());
    assert!(!sym.is_function());
    assert!(!sym.is_object());
    assert!(!sym.is_undefined());
    assert_eq!(sym.sym_type(), sym_type::STT_TLS);
}

#[test]
fn test_symbol_info_encoding() {
    for bind in 0u8..4 {
        for stype in 0u8..8 {
            let info = (bind << 4) | stype;
            let mut sym = Symbol::default();
            sym.st_info = info;
            assert_eq!(sym.binding(), bind);
            assert_eq!(sym.sym_type(), stype);
        }
    }
}

#[test]
fn test_symbol_max_values() {
    let mut sym = Symbol::default();
    sym.st_name = u32::MAX;
    sym.st_info = 0xFF;
    sym.st_other = 0xFF;
    sym.st_shndx = u16::MAX;
    sym.st_value = u64::MAX;
    sym.st_size = u64::MAX;

    assert_eq!(sym.st_name, u32::MAX);
    assert_eq!(sym.binding(), 0x0F);
    assert_eq!(sym.sym_type(), 0x0F);
    assert_eq!(sym.st_shndx, u16::MAX);
    assert_eq!(sym.st_value, u64::MAX);
    assert_eq!(sym.st_size, u64::MAX);
}
