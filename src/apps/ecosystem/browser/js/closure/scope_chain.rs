extern crate alloc;
use super::super::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

#[derive(Clone, Debug)]
pub struct LexicalScope {
    pub bindings: RefCell<BTreeMap<String, JsValue>>,
    pub parent: Option<Rc<LexicalScope>>,
}

pub struct ScopeChain;

impl LexicalScope {
    pub fn new() -> Rc<Self> {
        Rc::new(Self { bindings: RefCell::new(BTreeMap::new()), parent: None })
    }

    pub fn child(parent: Rc<Self>) -> Rc<Self> {
        Rc::new(Self { bindings: RefCell::new(BTreeMap::new()), parent: Some(parent) })
    }
}

impl ScopeChain {
    pub fn lookup(scope: &Rc<LexicalScope>, name: &str) -> Option<JsValue> {
        if let Some(val) = scope.bindings.borrow().get(name) {
            return Some(val.clone());
        }
        if let Some(ref parent) = scope.parent {
            return Self::lookup(parent, name);
        }
        None
    }

    pub fn assign(scope: &Rc<LexicalScope>, name: &str, value: JsValue) -> bool {
        if scope.bindings.borrow().contains_key(name) {
            scope.bindings.borrow_mut().insert(String::from(name), value);
            return true;
        }
        if let Some(ref parent) = scope.parent {
            return Self::assign(parent, name, value);
        }
        false
    }

    pub fn declare(scope: &Rc<LexicalScope>, name: String, value: JsValue) {
        scope.bindings.borrow_mut().insert(name, value);
    }

    pub fn depth(scope: &Rc<LexicalScope>) -> u32 {
        let mut d = 0u32;
        let mut current = scope.parent.clone();
        while let Some(p) = current {
            d += 1;
            current = p.parent.clone();
        }
        d
    }
}
