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
use super::types::{BinOp, Expr, Stmt, Token, UnaryOp};
use alloc::{boxed::Box, string::String, vec::Vec};

pub fn parse(tokens: &[Token]) -> Vec<Stmt> {
    let (mut pos, mut stmts) = (0, Vec::new());
    while pos < tokens.len() && tokens[pos] != Token::Eof {
        skip_nl(tokens, &mut pos);
        if pos < tokens.len() && tokens[pos] != Token::Eof {
            if let Some(s) = parse_stmt(tokens, &mut pos) {
                stmts.push(s);
            }
        }
    }
    stmts
}

fn skip_nl(t: &[Token], p: &mut usize) {
    while *p < t.len() && t[*p] == Token::Newline {
        *p += 1;
    }
}
fn expect(t: &[Token], p: &mut usize, e: &Token) {
    if t.get(*p) == Some(e) {
        *p += 1;
    }
}
fn at_end(t: &[Token], p: usize) -> bool {
    matches!(t.get(p), None | Some(Token::Newline | Token::Semi | Token::Eof))
}

fn parse_stmt(t: &[Token], p: &mut usize) -> Option<Stmt> {
    skip_nl(t, p);
    match &t.get(*p)? {
        Token::If => {
            *p += 1;
            let c = parse_expr(t, p);
            expect(t, p, &Token::Then);
            let th = parse_block(t, p, &[Token::Else, Token::Fi]);
            let el = if t.get(*p) == Some(&Token::Else) {
                *p += 1;
                parse_block(t, p, &[Token::Fi])
            } else {
                Vec::new()
            };
            expect(t, p, &Token::Fi);
            Some(Stmt::If { cond: c, then_block: th, else_block: el })
        }
        Token::For => {
            *p += 1;
            let v = if let Token::Ident(n) = &t[*p] {
                let x = n.clone();
                *p += 1;
                x
            } else {
                return None;
            };
            expect(t, p, &Token::In);
            let mut it = Vec::new();
            while t.get(*p) != Some(&Token::Do) {
                it.push(parse_expr(t, p));
            }
            expect(t, p, &Token::Do);
            let b = parse_block(t, p, &[Token::Done]);
            expect(t, p, &Token::Done);
            Some(Stmt::For { var: v, items: it, body: b })
        }
        Token::While => {
            *p += 1;
            let c = parse_expr(t, p);
            expect(t, p, &Token::Do);
            let b = parse_block(t, p, &[Token::Done]);
            expect(t, p, &Token::Done);
            Some(Stmt::While { cond: c, body: b })
        }
        Token::Return => {
            *p += 1;
            let v = if !at_end(t, *p) { Some(parse_expr(t, p)) } else { None };
            Some(Stmt::Return { value: v })
        }
        Token::Ident(n) if t.get(*p + 1) == Some(&Token::Assign) => {
            let x = n.clone();
            *p += 2;
            Some(Stmt::Assign { name: x, value: parse_expr(t, p) })
        }
        Token::Ident(n) => {
            let x = n.clone();
            *p += 1;
            let mut a = Vec::new();
            while !at_end(t, *p) {
                a.push(parse_expr(t, p));
            }
            Some(Stmt::Cmd { name: x, args: a })
        }
        _ => {
            *p += 1;
            None
        }
    }
}

fn parse_block(t: &[Token], p: &mut usize, ends: &[Token]) -> Vec<Stmt> {
    let mut s = Vec::new();
    while *p < t.len() && !ends.contains(&t[*p]) {
        skip_nl(t, p);
        if *p < t.len() && !ends.contains(&t[*p]) {
            if let Some(x) = parse_stmt(t, p) {
                s.push(x);
            }
        }
    }
    s
}

fn parse_expr(t: &[Token], p: &mut usize) -> Expr {
    let mut l = parse_cmp(t, p);
    loop {
        match t.get(*p) {
            Some(Token::And) => {
                *p += 1;
                l = Expr::BinOp {
                    op: BinOp::And,
                    left: Box::new(l),
                    right: Box::new(parse_cmp(t, p)),
                };
            }
            Some(Token::Or) => {
                *p += 1;
                l = Expr::BinOp {
                    op: BinOp::Or,
                    left: Box::new(l),
                    right: Box::new(parse_cmp(t, p)),
                };
            }
            _ => break,
        }
    }
    l
}

fn parse_cmp(t: &[Token], p: &mut usize) -> Expr {
    let l = parse_primary(t, p);
    let op = match t.get(*p) {
        Some(Token::Eq) => BinOp::Eq,
        Some(Token::Ne) => BinOp::Ne,
        Some(Token::Lt) => BinOp::Lt,
        Some(Token::Gt) => BinOp::Gt,
        Some(Token::Le) => BinOp::Le,
        Some(Token::Ge) => BinOp::Ge,
        _ => return l,
    };
    *p += 1;
    Expr::BinOp { op, left: Box::new(l), right: Box::new(parse_primary(t, p)) }
}

fn parse_primary(t: &[Token], p: &mut usize) -> Expr {
    match t.get(*p) {
        Some(Token::Num(n)) => {
            let v = *n;
            *p += 1;
            Expr::Num(v)
        }
        Some(Token::Str(s)) => {
            let v = s.clone();
            *p += 1;
            Expr::Str(v)
        }
        Some(Token::Dollar) => {
            *p += 1;
            if let Some(Token::Ident(n)) = t.get(*p) {
                let v = n.clone();
                *p += 1;
                Expr::Var(v)
            } else {
                Expr::Str(String::new())
            }
        }
        Some(Token::Ident(n)) => {
            let v = n.clone();
            *p += 1;
            Expr::Str(v)
        }
        Some(Token::Not) => {
            *p += 1;
            Expr::UnaryOp { op: UnaryOp::Not, expr: Box::new(parse_primary(t, p)) }
        }
        Some(Token::LParen) => {
            *p += 1;
            let e = parse_expr(t, p);
            expect(t, p, &Token::RParen);
            e
        }
        _ => Expr::Str(String::new()),
    }
}
