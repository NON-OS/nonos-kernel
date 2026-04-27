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

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Program {
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Expr(Expr),
    Block(Vec<Stmt>),
    Empty,
    Var { kind: VarKind, decls: Vec<VarDecl> },
    If { cond: Expr, then_br: Box<Stmt>, else_br: Option<Box<Stmt>> },
    While { cond: Expr, body: Box<Stmt> },
    DoWhile { body: Box<Stmt>, cond: Expr },
    For { init: Option<Box<Stmt>>, cond: Option<Expr>, update: Option<Expr>, body: Box<Stmt> },
    ForIn { left: Box<Stmt>, right: Expr, body: Box<Stmt> },
    ForOf { left: Box<Stmt>, right: Expr, body: Box<Stmt> },
    Break(Option<String>),
    Continue(Option<String>),
    Return(Option<Expr>),
    Throw(Expr),
    Try { block: Box<Stmt>, catch: Option<CatchClause>, finally: Option<Box<Stmt>> },
    Switch { discrim: Expr, cases: Vec<SwitchCase> },
    Function { name: Option<String>, params: Vec<String>, body: Box<Stmt>, is_async: bool },
    Class { name: Option<String>, super_class: Option<Expr>, body: Vec<ClassMember> },
    Debugger,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VarKind {
    Var,
    Let,
    Const,
}
#[derive(Debug, Clone)]
pub struct VarDecl {
    pub name: String,
    pub init: Option<Expr>,
}
#[derive(Debug, Clone)]
pub struct CatchClause {
    pub param: Option<String>,
    pub body: Box<Stmt>,
}
#[derive(Debug, Clone)]
pub struct SwitchCase {
    pub test: Option<Expr>,
    pub body: Vec<Stmt>,
}
#[derive(Debug, Clone)]
pub enum ClassMember {
    Method { name: String, params: Vec<String>, body: Box<Stmt>, is_static: bool, kind: MethodKind },
    Field { name: String, value: Option<Expr>, is_static: bool },
}
#[derive(Debug, Clone, Copy)]
pub enum MethodKind {
    Normal,
    Get,
    Set,
    Constructor,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Literal(Literal),
    Ident(String),
    This,
    Super,
    Array(Vec<Option<Expr>>),
    Object(Vec<Property>),
    Member { obj: Box<Expr>, prop: Box<Expr>, computed: bool },
    Call { callee: Box<Expr>, args: Vec<Expr> },
    New { callee: Box<Expr>, args: Vec<Expr> },
    Unary { op: UnaryOp, arg: Box<Expr>, prefix: bool },
    Binary { op: BinaryOp, left: Box<Expr>, right: Box<Expr> },
    Logical { op: LogicalOp, left: Box<Expr>, right: Box<Expr> },
    Conditional { test: Box<Expr>, consequent: Box<Expr>, alternate: Box<Expr> },
    Assign { op: AssignOp, left: Box<Expr>, right: Box<Expr> },
    Sequence(Vec<Expr>),
    Function { name: Option<String>, params: Vec<String>, body: Box<Stmt>, is_async: bool },
    Arrow { params: Vec<String>, body: ArrowBody, is_async: bool },
    Await(Box<Expr>),
    Yield { arg: Option<Box<Expr>>, delegate: bool },
    Spread(Box<Expr>),
    TaggedTemplate { tag: Box<Expr>, quasi: TemplateLit },
    Template(TemplateLit),
}

#[derive(Debug, Clone)]
pub enum Literal {
    Null,
    Undefined,
    Bool(bool),
    Number(f64),
    String(String),
    Regex { pattern: String, flags: String },
}
#[derive(Debug, Clone)]
pub struct Property {
    pub key: Expr,
    pub value: Expr,
    pub kind: PropKind,
    pub shorthand: bool,
    pub computed: bool,
}
#[derive(Debug, Clone, Copy)]
pub enum PropKind {
    Init,
    Get,
    Set,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnaryOp {
    Minus,
    Plus,
    Not,
    BitNot,
    Typeof,
    Void,
    Delete,
    PrefixInc,
    PrefixDec,
    PostfixInc,
    PostfixDec,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Ushr,
    Eq,
    Ne,
    StrictEq,
    StrictNe,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Instanceof,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogicalOp {
    And,
    Or,
    NullishCoalesce,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AssignOp {
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    ModAssign,
    AndAssign,
    OrAssign,
    XorAssign,
}
#[derive(Debug, Clone)]
pub enum ArrowBody {
    Expr(Box<Expr>),
    Block(Box<Stmt>),
}
#[derive(Debug, Clone)]
pub struct TemplateLit {
    pub quasis: Vec<String>,
    pub exprs: Vec<Expr>,
}
