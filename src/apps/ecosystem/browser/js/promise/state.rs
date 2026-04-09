extern crate alloc;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use super::super::runtime::JsValue;

#[derive(Clone, Debug)]
pub enum PromiseState {
    Pending,
    Fulfilled(JsValue),
    Rejected(JsValue),
}

#[derive(Clone)]
pub struct JsPromise {
    pub state: Rc<RefCell<PromiseState>>,
    pub on_fulfilled: Rc<RefCell<Vec<JsValue>>>,
    pub on_rejected: Rc<RefCell<Vec<JsValue>>>,
}

impl JsPromise {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(PromiseState::Pending)),
            on_fulfilled: Rc::new(RefCell::new(Vec::new())),
            on_rejected: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn resolved(value: JsValue) -> Self {
        Self {
            state: Rc::new(RefCell::new(PromiseState::Fulfilled(value))),
            on_fulfilled: Rc::new(RefCell::new(Vec::new())),
            on_rejected: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn rejected(reason: JsValue) -> Self {
        Self {
            state: Rc::new(RefCell::new(PromiseState::Rejected(reason))),
            on_fulfilled: Rc::new(RefCell::new(Vec::new())),
            on_rejected: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn resolve(&self, value: JsValue) {
        let mut state = self.state.borrow_mut();
        if matches!(*state, PromiseState::Pending) {
            *state = PromiseState::Fulfilled(value);
        }
    }

    pub fn reject(&self, reason: JsValue) {
        let mut state = self.state.borrow_mut();
        if matches!(*state, PromiseState::Pending) {
            *state = PromiseState::Rejected(reason);
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(*self.state.borrow(), PromiseState::Pending)
    }

    pub fn is_settled(&self) -> bool {
        !self.is_pending()
    }
}
