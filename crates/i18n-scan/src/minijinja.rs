// Copyright 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

pub use minijinja::machinery::parse;
use minijinja::{
    ErrorKind,
    machinery::ast::{Call, CallArg, Const, Expr, Macro, Spanned, Stmt},
};

use crate::key::{Context, Key};

/// Top-level entry: walk a single statement and record any translation keys
/// discovered within.
pub fn find_in_stmt<'a>(context: &mut Context, stmt: &'a Stmt<'a>) -> Result<(), minijinja::Error> {
    dispatch_stmt(context, stmt)
}

// ── Statement visitors ──────────────────────────────────────────────

fn dispatch_stmt<'a>(ctx: &mut Context, stmt: &'a Stmt<'a>) -> Result<(), minijinja::Error> {
    match stmt {
        Stmt::Template(tpl) => visit_stmt_list(ctx, &tpl.children),
        Stmt::EmitExpr(emit) => visit_expr(ctx, &emit.expr),
        Stmt::EmitRaw(_) => Ok(()),

        Stmt::ForLoop(fl) => {
            visit_expr(ctx, &fl.iter)?;
            visit_optional_expr(ctx, fl.filter_expr.as_ref())?;
            visit_expr(ctx, &fl.target)?;
            visit_stmt_list(ctx, &fl.body)?;
            visit_stmt_list(ctx, &fl.else_body)
        }

        Stmt::IfCond(ic) => {
            visit_expr(ctx, &ic.expr)?;
            visit_stmt_list(ctx, &ic.true_body)?;
            visit_stmt_list(ctx, &ic.false_body)
        }

        Stmt::WithBlock(wb) => {
            visit_stmt_list(ctx, &wb.body)?;
            for (lhs, rhs) in &wb.assignments {
                visit_expr(ctx, lhs)?;
                visit_expr(ctx, rhs)?;
            }
            Ok(())
        }

        Stmt::Set(set) => {
            visit_expr(ctx, &set.target)?;
            visit_expr(ctx, &set.expr)
        }

        Stmt::SetBlock(sb) => {
            visit_expr(ctx, &sb.target)?;
            visit_stmt_list(ctx, &sb.body)?;
            visit_optional_expr(ctx, sb.filter.as_ref())
        }

        Stmt::AutoEscape(ae) => {
            visit_expr(ctx, &ae.enabled)?;
            visit_stmt_list(ctx, &ae.body)
        }

        Stmt::FilterBlock(fb) => {
            visit_expr(ctx, &fb.filter)?;
            visit_stmt_list(ctx, &fb.body)
        }

        Stmt::Block(blk) => visit_stmt_list(ctx, &blk.body),

        Stmt::Import(imp) => {
            visit_expr(ctx, &imp.name)?;
            visit_expr(ctx, &imp.expr)
        }

        Stmt::FromImport(fi) => {
            visit_expr(ctx, &fi.expr)?;
            for (name_expr, alias_expr) in &fi.names {
                visit_expr(ctx, name_expr)?;
                visit_optional_expr(ctx, alias_expr.as_ref())?;
            }
            Ok(())
        }

        Stmt::Extends(ext) => visit_expr(ctx, &ext.name),
        Stmt::Include(inc) => visit_expr(ctx, &inc.name),

        Stmt::Macro(mac) => visit_macro_decl(ctx, mac),

        Stmt::CallBlock(cb) => {
            visit_call_spanned(ctx, &cb.call)?;
            visit_macro_decl(ctx, &cb.macro_decl)
        }

        Stmt::Do(do_stmt) => visit_call_spanned(ctx, &do_stmt.call),
    }
}

// ── Macro helpers ───────────────────────────────────────────────────

fn visit_macro_decl<'a>(ctx: &mut Context, mac: &'a Macro<'a>) -> Result<(), minijinja::Error> {
    visit_stmt_list(ctx, &mac.body)?;
    visit_expr_list(ctx, &mac.args)?;
    visit_expr_list(ctx, &mac.defaults)
}

// ── Call handling (where translation keys are extracted) ─────────────

fn visit_call_spanned<'a>(
    ctx: &mut Context,
    call: &'a Spanned<Call<'a>>,
) -> Result<(), minijinja::Error> {
    let source_span = call.span();

    // Detect whether this call invokes the translation function.
    if let Expr::Var(v) = &call.expr {
        if v.id == ctx.func() {
            record_translation_key(ctx, &call.args, source_span)?;
        }
    }

    visit_expr(ctx, &call.expr)?;
    visit_call_arg_list(ctx, &call.args)
}

/// Extract the translation key from the first positional argument of
/// a call to the translation function.
fn record_translation_key<'a>(
    ctx: &mut Context,
    args: &'a [CallArg<'a>],
    span: minijinja::machinery::Span,
) -> Result<(), minijinja::Error> {
    let first_arg = args.first().and_then(extract_const_from_call_arg);

    let key_str = first_arg.and_then(|c| c.value.as_str()).ok_or_else(|| {
        minijinja::Error::new(
            ErrorKind::UndefinedError,
            "t() first argument must be a string literal",
        )
    })?;

    let is_plural = args.iter().any(|a| matches!(a, CallArg::Kwarg("count", _)));

    let kind = if is_plural {
        crate::key::Kind::Plural
    } else {
        crate::key::Kind::Message
    };

    let mut key = Key::new(kind, key_str.to_owned());
    key = ctx.set_key_location(key, span);
    ctx.record(key);

    Ok(())
}

fn extract_const_from_call_arg<'a>(arg: &'a CallArg<'a>) -> Option<&'a Const> {
    match arg {
        CallArg::Pos(Expr::Const(c)) => Some(c),
        _ => None,
    }
}

// ── Call-argument visitors ──────────────────────────────────────────

fn visit_call_arg_list<'a>(
    ctx: &mut Context,
    args: &'a [CallArg<'a>],
) -> Result<(), minijinja::Error> {
    for arg in args {
        visit_single_call_arg(ctx, arg)?;
    }
    Ok(())
}

fn visit_single_call_arg<'a>(
    ctx: &mut Context,
    arg: &'a CallArg<'a>,
) -> Result<(), minijinja::Error> {
    let inner = match arg {
        CallArg::Pos(e) | CallArg::Kwarg(_, e) | CallArg::PosSplat(e) | CallArg::KwargSplat(e) => e,
    };
    visit_expr(ctx, inner)
}

// ── Statement / expression list visitors ────────────────────────────

fn visit_stmt_list<'a>(ctx: &mut Context, stmts: &'a [Stmt<'a>]) -> Result<(), minijinja::Error> {
    for s in stmts {
        dispatch_stmt(ctx, s)?;
    }
    Ok(())
}

fn visit_expr_list<'a>(ctx: &mut Context, exprs: &'a [Expr<'a>]) -> Result<(), minijinja::Error> {
    for e in exprs {
        visit_expr(ctx, e)?;
    }
    Ok(())
}

fn visit_optional_expr<'a>(
    ctx: &mut Context,
    maybe: Option<&'a Expr<'a>>,
) -> Result<(), minijinja::Error> {
    if let Some(e) = maybe {
        visit_expr(ctx, e)?;
    }
    Ok(())
}

// ── Expression visitor ──────────────────────────────────────────────

fn visit_expr<'a>(ctx: &mut Context, expr: &'a Expr<'a>) -> Result<(), minijinja::Error> {
    match expr {
        Expr::Var(_) | Expr::Const(_) => Ok(()),

        Expr::Slice(sl) => {
            visit_expr(ctx, &sl.expr)?;
            visit_optional_expr(ctx, sl.start.as_ref())?;
            visit_optional_expr(ctx, sl.stop.as_ref())?;
            visit_optional_expr(ctx, sl.step.as_ref())
        }

        Expr::UnaryOp(uo) => visit_expr(ctx, &uo.expr),

        Expr::BinOp(bo) => {
            visit_expr(ctx, &bo.left)?;
            visit_expr(ctx, &bo.right)
        }

        Expr::IfExpr(ie) => {
            visit_expr(ctx, &ie.test_expr)?;
            visit_expr(ctx, &ie.true_expr)?;
            visit_optional_expr(ctx, ie.false_expr.as_ref())
        }

        Expr::Filter(flt) => {
            visit_optional_expr(ctx, flt.expr.as_ref())?;
            visit_call_arg_list(ctx, &flt.args)
        }

        Expr::Test(tst) => {
            visit_expr(ctx, &tst.expr)?;
            visit_call_arg_list(ctx, &tst.args)
        }

        Expr::GetAttr(ga) => visit_expr(ctx, &ga.expr),

        Expr::GetItem(gi) => {
            visit_expr(ctx, &gi.expr)?;
            visit_expr(ctx, &gi.subscript_expr)
        }

        Expr::Call(call) => visit_call_spanned(ctx, call),

        Expr::List(lst) => visit_expr_list(ctx, &lst.items),

        Expr::Map(map) => {
            visit_expr_list(ctx, &map.keys)?;
            visit_expr_list(ctx, &map.values)
        }
    }
}

#[cfg(test)]
mod tests {
    use minijinja::{machinery::WhitespaceConfig, syntax::SyntaxConfig};

    use super::*;

    #[test]
    fn test_find_keys() {
        let mut context = Context::new("t".to_owned());
        let templates = [
            ("hello.txt", r#"Hello {{ t("world") }}"#),
            ("existing.txt", r#"{{ t("hello") }}"#),
            ("plural.txt", r#"{{ t("plural", count=4) }}"#),
            // Kitchen sink to make sure we're going through the whole AST
            (
                "macros.txt",
                r#"
                    {% macro test(arg="foo") %}
                        {% if function() == foo is test(t("nested.1")) %}
                            {% set foo = t("nested.2", arg=5 + 2) ~ "foo" in test %}
                            {{ foo | bar }}
                        {% else %}
                            {% for i in [t("nested.3", extra=t("nested.4")), "foo"] %}
                                {{ i | foo }}
                            {% else %}
                                {{ t("nested.5") }}
                            {% endfor %}
                        {% endif %}
                    {% endmacro %}
                "#,
            ),
            (
                "nested.txt",
                r#"
                    {% import "macros.txt" as macros %}
                    {% block test %}
                        {% filter upper %}
                            {{ macros.test(arg=t("nested.6")) }}
                        {% endfilter %}
                    {% endblock test %}
                "#,
            ),
        ];

        for (name, content) in templates {
            let ast = parse(
                content,
                name,
                SyntaxConfig::default(),
                WhitespaceConfig::default(),
            )
            .unwrap();
            find_in_stmt(&mut context, &ast).unwrap();
        }

        let keys = context.ftl_keys();
        // Keys should be sorted and deduplicated, with dots converted to hyphens
        assert_eq!(
            keys,
            vec![
                "hello", "nested-1", "nested-2", "nested-3", "nested-4", "nested-5", "nested-6",
                "plural", "world",
            ]
        );
    }

    #[test]
    fn test_invalid_key_not_string() {
        // This is invalid because the key is not a string
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r"{{ t(5) }}",
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_key_filtered() {
        // This is invalid because the key argument has a filter
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r#"{{ t("foo" | bar) }}"#,
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_key_missing() {
        // This is invalid because the key argument is missing
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r"{{ t() }}",
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_key_negated() {
        // This is invalid because the key argument is missing
        let mut context = Context::new("t".to_owned());
        let ast = parse(
            r#"{{ t(not "foo") }}"#,
            "invalid.txt",
            SyntaxConfig::default(),
            WhitespaceConfig::default(),
        )
        .unwrap();

        let res = find_in_stmt(&mut context, &ast);
        assert!(res.is_err());
    }
}
