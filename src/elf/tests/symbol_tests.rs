use crate::elf::types::{sym_bind, sym_type, Symbol, SymbolEntry};
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_symbol_size() -> TestResult {
    if mem::size_of::<Symbol>() != Symbol::SIZE {
        return TestResult::Fail;
    }
    if Symbol::SIZE != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_entry_alias() -> TestResult {
    if mem::size_of::<SymbolEntry>() != Symbol::SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_default() -> TestResult {
    let sym = Symbol::default();
    if sym.st_name != 0 {
        return TestResult::Fail;
    }
    if sym.st_info != 0 {
        return TestResult::Fail;
    }
    if sym.st_other != 0 {
        return TestResult::Fail;
    }
    if sym.st_shndx != 0 {
        return TestResult::Fail;
    }
    if sym.st_value != 0 {
        return TestResult::Fail;
    }
    if sym.st_size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_binding_local() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    if sym.binding() != sym_bind::STB_LOCAL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_binding_global() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    if sym.binding() != sym_bind::STB_GLOBAL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_binding_weak() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    if sym.binding() != sym_bind::STB_WEAK {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_binding_with_type() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    if sym.binding() != sym_bind::STB_GLOBAL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_notype() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_NOTYPE;
    if sym.sym_type() != sym_type::STT_NOTYPE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_object() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_OBJECT;
    if sym.sym_type() != sym_type::STT_OBJECT {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_func() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FUNC;
    if sym.sym_type() != sym_type::STT_FUNC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_section() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_SECTION;
    if sym.sym_type() != sym_type::STT_SECTION {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_file() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FILE;
    if sym.sym_type() != sym_type::STT_FILE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_tls() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_TLS;
    if sym.sym_type() != sym_type::STT_TLS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_with_binding() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    if sym.sym_type() != sym_type::STT_FUNC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_local_true() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    if !sym.is_local() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_local_false_global() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    if sym.is_local() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_local_false_weak() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    if sym.is_local() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_global_true() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    if !sym.is_global() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_global_false_local() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    if sym.is_global() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_global_false_weak() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    if sym.is_global() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_weak_true() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_WEAK << 4;
    if !sym.is_weak() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_weak_false_local() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_LOCAL << 4;
    if sym.is_weak() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_weak_false_global() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_bind::STB_GLOBAL << 4;
    if sym.is_weak() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_function_true() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FUNC;
    if !sym.is_function() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_function_false_object() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_OBJECT;
    if sym.is_function() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_function_false_notype() -> TestResult {
    let sym = Symbol::default();
    if sym.is_function() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_function_with_binding() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    if !sym.is_function() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_object_true() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_OBJECT;
    if !sym.is_object() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_object_false_func() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = sym_type::STT_FUNC;
    if sym.is_object() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_object_false_notype() -> TestResult {
    let sym = Symbol::default();
    if sym.is_object() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_object_with_binding() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_OBJECT;
    if !sym.is_object() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_undefined_true() -> TestResult {
    let sym = Symbol::default();
    if !sym.is_undefined() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_undefined_false() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_shndx = 1;
    if sym.is_undefined() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_undefined_false_shndx_max() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_shndx = 0xFFFF;
    if sym.is_undefined() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_clone() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_value = 0x401000;
    sym.st_size = 100;
    let cloned = sym;
    if cloned.st_value != 0x401000 {
        return TestResult::Fail;
    }
    if cloned.st_size != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_copy() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_name = 42;
    let copied: Symbol = sym;
    if copied.st_name != 42 {
        return TestResult::Fail;
    }
    if sym.st_name != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_alignment() -> TestResult {
    if mem::align_of::<Symbol>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_bind_constants() -> TestResult {
    if sym_bind::STB_LOCAL != 0 {
        return TestResult::Fail;
    }
    if sym_bind::STB_GLOBAL != 1 {
        return TestResult::Fail;
    }
    if sym_bind::STB_WEAK != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sym_type_constants() -> TestResult {
    if sym_type::STT_NOTYPE != 0 {
        return TestResult::Fail;
    }
    if sym_type::STT_OBJECT != 1 {
        return TestResult::Fail;
    }
    if sym_type::STT_FUNC != 2 {
        return TestResult::Fail;
    }
    if sym_type::STT_SECTION != 3 {
        return TestResult::Fail;
    }
    if sym_type::STT_FILE != 4 {
        return TestResult::Fail;
    }
    if sym_type::STT_TLS != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_global_function() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_name = 10;
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    sym.st_shndx = 1;
    sym.st_value = 0x401000;
    sym.st_size = 256;

    if !sym.is_global() {
        return TestResult::Fail;
    }
    if sym.is_local() {
        return TestResult::Fail;
    }
    if sym.is_weak() {
        return TestResult::Fail;
    }
    if !sym.is_function() {
        return TestResult::Fail;
    }
    if sym.is_object() {
        return TestResult::Fail;
    }
    if sym.is_undefined() {
        return TestResult::Fail;
    }
    if sym.binding() != sym_bind::STB_GLOBAL {
        return TestResult::Fail;
    }
    if sym.sym_type() != sym_type::STT_FUNC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_weak_object() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_name = 20;
    sym.st_info = (sym_bind::STB_WEAK << 4) | sym_type::STT_OBJECT;
    sym.st_shndx = 2;
    sym.st_value = 0x600000;
    sym.st_size = 8;

    if sym.is_global() {
        return TestResult::Fail;
    }
    if sym.is_local() {
        return TestResult::Fail;
    }
    if !sym.is_weak() {
        return TestResult::Fail;
    }
    if sym.is_function() {
        return TestResult::Fail;
    }
    if !sym.is_object() {
        return TestResult::Fail;
    }
    if sym.is_undefined() {
        return TestResult::Fail;
    }
    if sym.binding() != sym_bind::STB_WEAK {
        return TestResult::Fail;
    }
    if sym.sym_type() != sym_type::STT_OBJECT {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_local_section() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_LOCAL << 4) | sym_type::STT_SECTION;
    sym.st_shndx = 5;
    sym.st_value = 0x400000;

    if !sym.is_local() {
        return TestResult::Fail;
    }
    if sym.is_global() {
        return TestResult::Fail;
    }
    if sym.is_weak() {
        return TestResult::Fail;
    }
    if sym.is_function() {
        return TestResult::Fail;
    }
    if sym.is_object() {
        return TestResult::Fail;
    }
    if sym.is_undefined() {
        return TestResult::Fail;
    }
    if sym.sym_type() != sym_type::STT_SECTION {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_undefined_import() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_name = 50;
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;
    sym.st_shndx = 0;
    sym.st_value = 0;
    sym.st_size = 0;

    if !sym.is_global() {
        return TestResult::Fail;
    }
    if !sym.is_function() {
        return TestResult::Fail;
    }
    if !sym.is_undefined() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_tls_variable() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_TLS;
    sym.st_shndx = 7;
    sym.st_value = 0;
    sym.st_size = 4;

    if !sym.is_global() {
        return TestResult::Fail;
    }
    if sym.is_function() {
        return TestResult::Fail;
    }
    if sym.is_object() {
        return TestResult::Fail;
    }
    if sym.is_undefined() {
        return TestResult::Fail;
    }
    if sym.sym_type() != sym_type::STT_TLS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_info_encoding() -> TestResult {
    for bind in 0u8..4 {
        for stype in 0u8..8 {
            let info = (bind << 4) | stype;
            let mut sym = Symbol::default();
            sym.st_info = info;
            if sym.binding() != bind {
                return TestResult::Fail;
            }
            if sym.sym_type() != stype {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_symbol_max_values() -> TestResult {
    let mut sym = Symbol::default();
    sym.st_name = u32::MAX;
    sym.st_info = 0xFF;
    sym.st_other = 0xFF;
    sym.st_shndx = u16::MAX;
    sym.st_value = u64::MAX;
    sym.st_size = u64::MAX;

    if sym.st_name != u32::MAX {
        return TestResult::Fail;
    }
    if sym.binding() != 0x0F {
        return TestResult::Fail;
    }
    if sym.sym_type() != 0x0F {
        return TestResult::Fail;
    }
    if sym.st_shndx != u16::MAX {
        return TestResult::Fail;
    }
    if sym.st_value != u64::MAX {
        return TestResult::Fail;
    }
    if sym.st_size != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}
