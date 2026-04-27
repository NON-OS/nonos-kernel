extern crate alloc;
use super::super::runtime::JsValue;
use super::scope_chain::{LexicalScope, ScopeChain};
use alloc::rc::Rc;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    Let,
    Const,
    Var,
}

pub fn declare_binding(scope: &Rc<LexicalScope>, name: String, value: JsValue, kind: BindingKind) {
    match kind {
        BindingKind::Let | BindingKind::Const => {
            ScopeChain::declare(scope, name, value);
        }
        BindingKind::Var => {
            hoist_to_function_scope(scope, name, value);
        }
    }
}

fn hoist_to_function_scope(scope: &Rc<LexicalScope>, name: String, value: JsValue) {
    let mut target = scope.clone();
    while let Some(ref parent) = target.clone().parent {
        target = parent.clone();
    }
    ScopeChain::declare(&target, name, value);
}
