// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// AGPL-3.0-or-later

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    If,
    Then,
    Else,
    Fi,
    For,
    In,
    Do,
    Done,
    While,
    Fn,
    Return,
    Ident(String),
    Str(String),
    Num(i64),
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
    Not,
    Assign,
    Semi,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Pipe,
    Amp,
    Newline,
    Dollar,
    Comma,
    Eof,
}

#[derive(Clone, Debug)]
pub enum Stmt {
    Assign { name: String, value: Expr },
    If { cond: Expr, then_block: Vec<Stmt>, else_block: Vec<Stmt> },
    For { var: String, items: Vec<Expr>, body: Vec<Stmt> },
    While { cond: Expr, body: Vec<Stmt> },
    Fn { name: String, params: Vec<String>, body: Vec<Stmt> },
    Return { value: Option<Expr> },
    Cmd { name: String, args: Vec<Expr> },
    Expr(Expr),
}

#[derive(Clone, Debug)]
pub enum Expr {
    Num(i64),
    Str(String),
    Var(String),
    Bool(bool),
    BinOp { op: BinOp, left: Box<Expr>, right: Box<Expr> },
    UnaryOp { op: UnaryOp, expr: Box<Expr> },
    Call { name: String, args: Vec<Expr> },
    List(Vec<Expr>),
}

#[derive(Clone, Debug)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
}

#[derive(Clone, Debug)]
pub enum UnaryOp {
    Neg,
    Not,
}

#[derive(Clone, Debug)]
pub enum Value {
    Num(i64),
    Str(String),
    Bool(bool),
    List(Vec<Value>),
    None,
}

impl Value {
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Num(n) => *n != 0,
            Value::Str(s) => !s.is_empty(),
            Value::Bool(b) => *b,
            Value::List(l) => !l.is_empty(),
            Value::None => false,
        }
    }
}
