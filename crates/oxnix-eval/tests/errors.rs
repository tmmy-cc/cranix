//! Snapshot tests for the rendering of evaluation errors.

use std::rc::Rc;

use oxnix_eval::{Eval, Options, RenderOptions};
use oxnix_store::Store;

fn eval() -> Rc<Eval> {
    let root = std::env::temp_dir().join(format!("oxnix-error-tests-{}", std::process::id()));
    let store = Store::open_at(&root).expect("opening a temporary store");
    let opts = Options { search_path: Vec::new(), system: "x86_64-linux".into(), pure: true, trace_verbose: false, experimental_features: Default::default(), resolve_search: None };
    Eval::new(store, opts)
}

/// The rendered error of evaluating `src` strictly.
fn render(src: &str, show_trace: bool) -> String {
    let ev = eval();
    let e = ev.eval_string(src, "/").and_then(|v| ev.deep_force(&v)).err().expect("evaluation should fail");
    ev.render_error(&e, &RenderOptions { show_trace, color: false })
}

#[track_caller]
fn check(src: &str, want: &str) {
    let got = render(src, false);
    assert_eq!(got, want.strip_prefix('\n').unwrap(), "\n--- got ---\n{got}\n");
}

#[test]
fn undefined_variable_suggests_names_in_scope() {
    check(
        "let longName = 1; in longNme",
        r#"
error: undefined variable 'longNme'
       at «string»:1:22:
            1| let longName = 1; in longNme
             |                      ^
       Did you mean longName?"#,
    );
}

#[test]
fn undefined_variable_suggests_with_attributes() {
    check(
        "with { abc = 1; }; abd",
        r#"
error: undefined variable 'abd'
       at «string»:1:20:
            1| with { abc = 1; }; abd
             |                    ^
       Did you mean abc?"#,
    );
}

#[test]
fn missing_attribute_suggests_close_names() {
    check(
        "let pkgs = { hello = 1; hellp = 2; foo = 3; };\nin pkgs.hallo",
        r#"
error: attribute 'hallo' missing
       at «string»:2:4:
            1| let pkgs = { hello = 1; hellp = 2; foo = 3; };
            2| in pkgs.hallo
             |    ^
       Did you mean one of hello or hellp?"#,
    );
}

#[test]
fn type_error_names_the_value() {
    check(
        "builtins.length 5",
        r#"
error:
       … while calling the 'length' builtin
         at «string»:1:1:
            1| builtins.length 5
             | ^

       error: expected a list but found an integer: 5"#,
    );
}

#[test]
fn values_in_messages_are_truncated() {
    check(
        "toString { a = [ 1 2 3 4 5 6 7 8 9 10 11 12 ]; b = 1 + 1; }",
        r#"
error:
       … while calling the 'toString' builtin
         at «string»:1:1:
            1| toString { a = [ 1 2 3 4 5 6 7 8 9 10 11 12 ]; b = 1 + 1; }
             | ^

       error: cannot coerce a set to a string: { a = «thunk»; b = «thunk»; }"#,
    );
    check(
        "[ 1 2 3 4 5 6 7 8 9 10 11 12 ] + 1",
        r#"
error: cannot coerce a list to a string: [ 1 2 3 4 5 6 7 8 9 10 «2 items elided» ]
       at «string»:1:32:
            1| [ 1 2 3 4 5 6 7 8 9 10 11 12 ] + 1
             |                                ^"#,
    );
}

#[test]
fn unexpected_argument_lists_valid_ones() {
    check(
        "let f = { src, version ? 1 }: src; in\nf { src = 1; source = 2; }",
        r#"
error:
       … from call site
         at «string»:2:1:
            1| let f = { src, version ? 1 }: src; in
            2| f { src = 1; source = 2; }
             | ^

       error: function 'f' called with unexpected argument 'source'
       at «string»:1:9:
            1| let f = { src, version ? 1 }: src; in
             |         ^
            2| f { src = 1; source = 2; }
       The function accepts 'src' and 'version'."#,
    );
}

#[test]
fn missing_argument_names_the_function() {
    check(
        "let f = { a, b }: a; in f { a = 1; bb = 2; }",
        r#"
error:
       … from call site
         at «string»:1:25:
            1| let f = { a, b }: a; in f { a = 1; bb = 2; }
             |                         ^

       error: function 'f' called without required argument 'b'
       at «string»:1:9:
            1| let f = { a, b }: a; in f { a = 1; bb = 2; }
             |         ^
       Did you mean to pass 'b' instead of 'bb'?"#,
    );
}

#[test]
fn assertion_shows_its_condition() {
    check(
        "let x = 1; in assert x > 1; x",
        r#"
error: assertion 'x > 1' failed
       at «string»:1:15:
            1| let x = 1; in assert x > 1; x
             |               ^"#,
    );
}

#[test]
fn infinite_recursion_points_at_the_attribute() {
    check(
        "let r = { a = r.a; }; in r.a",
        r#"
error:
       … while evaluating the attribute 'a'
         at «string»:1:26:
            1| let r = { a = r.a; }; in r.a
             |                          ^

       … while evaluating the attribute 'a'
         at «string»:1:15:
            1| let r = { a = r.a; }; in r.a
             |               ^

       error: infinite recursion encountered
       at «string»:1:15:
            1| let r = { a = r.a; }; in r.a
             |               ^"#,
    );
}

#[test]
fn operator_errors_name_the_operand() {
    check(
        "{ a = 1; } // 3",
        r#"
error: expected a set but found an integer in the right operand of the update (//) operator: 3
       at «string»:1:12:
            1| { a = 1; } // 3
             |            ^"#,
    );
    check(
        r#"1 + "a""#,
        r#"
error: cannot add a string to an integer: "a"
       at «string»:1:3:
            1| 1 + "a"
             |   ^"#,
    );
}

#[test]
fn parse_errors_say_what_was_expected() {
    check(
        "{ a = 1;",
        r#"
error: syntax error, unexpected end of file, expecting an attribute name, 'inherit' or '}'
       at «string»:1:9:
            1| { a = 1;
             |         ^"#,
    );
    check(
        "x: x x)",
        r#"
error: syntax error, unexpected ')', expecting end of file
       at «string»:1:7:
            1| x: x x)
             |       ^"#,
    );
}

#[test]
fn duplicate_attribute_names_the_first_definition() {
    check(
        "{ a = 2; a = 3; }",
        r#"
error: attribute 'a' already defined at «string»:1:3
       at «string»:1:10:
            1| { a = 2; a = 3; }
             |          ^"#,
    );
}

#[test]
fn short_trace_keeps_both_ends() {
    let src = "let s = { a = s.b; b = s.c; c = s.d; d = s.e; e = s.f; f = throw \"deep\"; }; in s.a";
    let short = render(src, false);
    assert!(short.contains("(3 frames omitted; use '--show-trace' to show the full, detailed trace)"), "{short}");
    assert!(short.contains("attribute 'a'") && short.contains("attribute 'f'"), "{short}");
    assert!(!short.contains("attribute 'c'"), "{short}");
    let full = render(src, true);
    assert!(!full.contains("omitted"), "{full}");
    for k in ["a", "b", "c", "d", "e", "f"] {
        assert!(full.contains(&format!("while evaluating the attribute '{k}'")), "{full}");
    }
}

#[test]
fn full_trace_collapses_repeated_frames() {
    let src = "let f = n: if n == 0 then throw \"bottom\" else f (n - 1); in f 5";
    let short = render(src, false);
    assert!(!short.contains("while calling 'f'"), "{short}");
    let full = render(src, true);
    assert_eq!(full.matches("while calling 'f'").count(), 1, "{full}");
    assert!(full.contains("(9 duplicate frames omitted)"), "{full}");
    assert!(full.ends_with("error: bottom"), "{full}");
}

#[test]
fn colour_marks_the_error_and_caret() {
    let ev = eval();
    let e = ev.eval_string("x", "/").err().unwrap();
    let out = ev.render_error(&e, &RenderOptions { show_trace: false, color: true });
    assert!(out.starts_with("\x1b[31;1merror:\x1b[0m undefined variable 'x'"), "{out:?}");
    assert!(out.contains("\x1b[31;1m^\x1b[0m"), "{out:?}");
}
