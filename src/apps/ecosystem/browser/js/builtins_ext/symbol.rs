extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

static NEXT_SYMBOL_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsSymbol {
    pub id: u32,
}

pub struct SymbolRegistry {
    named: BTreeMap<String, JsSymbol>,
}

impl JsSymbol {
    pub fn new() -> Self {
        Self { id: NEXT_SYMBOL_ID.fetch_add(1, Ordering::Relaxed) }
    }

    pub fn iterator() -> Self {
        Self { id: 0 }
    }

    pub fn is_iterator(&self) -> bool {
        self.id == 0
    }
}

impl SymbolRegistry {
    pub fn new() -> Self {
        Self { named: BTreeMap::new() }
    }

    pub fn symbol_for(&mut self, key: &str) -> JsSymbol {
        if let Some(sym) = self.named.get(key) {
            return *sym;
        }
        let sym = JsSymbol::new();
        self.named.insert(String::from(key), sym);
        sym
    }

    pub fn key_for(&self, symbol: JsSymbol) -> Option<&str> {
        for (key, sym) in &self.named {
            if *sym == symbol {
                return Some(key.as_str());
            }
        }
        None
    }
}
