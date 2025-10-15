//! Dynamic Linking Helpers for ELF Loader

use x86_64::VirtAddr;

/// Dynamic linking information for loaded ELF image.
#[derive(Debug, Clone)]
pub struct DynLinkInfo {
    /// List of required libraries for dynamic linking (DT_NEEDED).
    pub needed_libraries: Vec<String>,
    /// Address of the ELF symbol table (DT_SYMTAB).
    pub symbol_table: Option<VirtAddr>,
    /// Address of the ELF string table (DT_STRTAB).
    pub string_table: Option<VirtAddr>,
    /// Size of string table in bytes (DT_STRSZ).
    pub string_table_size: usize,
    /// Address of the RELA relocation table (DT_RELA).
    pub rela_table: Option<VirtAddr>,
    /// Size of RELA relocation table in bytes (DT_RELASZ).
    pub rela_size: usize,
    /// Address of PLT relocation table (DT_JMPREL).
    pub plt_relocations: Option<VirtAddr>,
    /// Size of PLT relocation table in bytes (DT_PLTRELSZ).
    pub plt_rela_size: usize,
    /// Address of the init function (DT_INIT).
    pub init_function: Option<VirtAddr>,
    /// Address of the fini function (DT_FINI).
    pub fini_function: Option<VirtAddr>,
}

impl DynLinkInfo {
    /// Create a new dynamic linking info struct.
    pub fn new() -> Self {
        Self {
            needed_libraries: Vec::new(),
            symbol_table: None,
            string_table: None,
            string_table_size: 0,
            rela_table: None,
            rela_size: 0,
            plt_relocations: None,
            plt_rela_size: 0,
            init_function: None,
            fini_function: None,
        }
    }
}
