1 + 2 * 3 - 4 / 2
#---
1.5 + 2
#---
"a" + "b"
#---
[ (1 < 2) (2 <= 2) ("a" < "b") ([1 2] < [1 3]) (1 == 1.0) ({a=1;} == {a=1;}) ]
#---
let f = { a, b ? a + 1, ... }@args: [ a b (args ? c) ]; in [ (f { a = 1; }) (f { a = 1; b = 5; c = 3; }) ]
#---
let x = { a.b.c = 1; a.b.d = 2; a.e = 3; }; in x
#---
rec { a = 1; b = a + c; c = 2; }
#---
with { x = 1; y = 2; }; x + y
#---
let x = 5; in with { x = 1; }; x
#---
{ ${"dyn" + "amic"} = 1; static = 2; ${null} = 3; }
#---
builtins.attrNames { z = 1; a = 2; m = 3; }
#---
builtins.map (x: x * 2) [ 1 2 3 ]
#---
builtins.filter (x: x > 1) [ 1 2 3 ]
#---
builtins.foldl' (a: b: a + b) 0 [ 1 2 3 4 ]
#---
builtins.genList (i: i * i) 5
#---
builtins.sort (a: b: a < b) [ 5 3 1 4 2 9 8 7 6 10 12 11 ]
#---
builtins.concatStringsSep ", " [ "a" "b" "c" ]
#---
builtins.replaceStrings [ "a" "b" ] [ "x" "yy" ] "aabbcc"
#---
builtins.replaceStrings [ "" ] [ "-" ] "abc"
#---
builtins.match "a(b)(c)?" "ab"
#---
builtins.match "([[:alpha:]]+)-([0-9.]+)" "hello-2.12.1"
#---
builtins.split "(a)|b" "xaybz"
#---
builtins.splitVersion "1.2.3pre4-rc1"
#---
[ (builtins.compareVersions "1.2" "1.10") (builtins.compareVersions "2.3pre1" "2.3") (builtins.compareVersions "1.0" "1.0") (builtins.compareVersions "2.3a" "2.3.1") ]
#---
builtins.parseDrvName "hello-2.12.1"
#---
builtins.parseDrvName "nix-unstable-2.3"
#---
builtins.substring 1 3 "hello world"
#---
builtins.stringLength "hello"
#---
builtins.hashString "sha256" "hello"
#---
builtins.hashString "md5" "hello"
#---
builtins.toJSON { a = [ 1 2.5 "x\n" null true ]; b = { c = "d"; }; }
#---
builtins.fromJSON ''{"a": [1, 2.5, "x", null, true], "b": {"c": "d"}}''
#---
builtins.listToAttrs [ { name = "a"; value = 1; } { name = "b"; value = 2; } { name = "a"; value = 3; } ]
#---
builtins.removeAttrs { a = 1; b = 2; c = 3; } [ "b" ]
#---
builtins.intersectAttrs { a = 0; c = 0; } { a = 1; b = 2; c = 3; }
#---
builtins.catAttrs "a" [ { a = 1; } { b = 2; } { a = 3; } ]
#---
builtins.mapAttrs (n: v: n + toString v) { a = 1; b = 2; }
#---
builtins.zipAttrsWith (n: vs: vs) [ { a = 1; } { a = 2; b = 3; } ]
#---
builtins.groupBy (x: if x > 2 then "big" else "small") [ 1 2 3 4 ]
#---
builtins.partition (x: x > 2) [ 1 2 3 4 ]
#---
builtins.tryEval (throw "boom")
#---
builtins.tryEval (assert false; 1)
#---
builtins.tryEval 42
#---
builtins.functionArgs ({ a, b ? 1 }: a)
#---
map builtins.typeOf [ 1 "a" {} [] null true 1.0 ./. (x: x) ]
#---
builtins.elemAt [ 1 2 3 ] 1
#---
builtins.concatLists [ [ 1 ] [ 2 3 ] [] ]
#---
builtins.concatMap (x: [ x x ]) [ 1 2 ]
#---
builtins.genericClosure { startSet = [ { key = 1; } ]; operator = x: if x.key < 5 then [ { key = x.key + 1; } ] else []; }
#---
toString [ 1 "a" [ ] null true false 2 ]
#---
toString 1.5
#---
"${toString 0.1}"
#---
builtins.toJSON 1.0
#---
builtins.toJSON 0.1
#---
''
  hello
    world
  ${"x"} done
''
#---
''  a''${b} '''c ''\n''
#---
"a\$b \${c} $${d}"
#---
let s = "x"; in ''${s}''
#---
''
    a
  b
     c
''
#---
''
  x
  ''
#---
[ (builtins.bitAnd 12 10) (builtins.bitOr 12 10) (builtins.bitXor 12 10) ]
#---
[ (builtins.baseNameOf "/a/b/c.txt") (builtins.dirOf "/a/b/c.txt") (builtins.dirOf "foo") ]
#---
[ (builtins.ceil 1.2) (builtins.floor 1.8) (-5 / 2) (builtins.div 7 2) ((x: x) 1) ]
#---
let fix = f: let x = f x; in x; in (fix (self: { a = 1; b = self.a + 1; })).b
#---
let a = { x = 1; }; in a // { y = 2; } // { x = 3; }
#---
[ ([ 1 2 ] ++ [ 3 ]) (!true || false && true) (true -> false) ({ a = 1; } ? a) ({ a.b = 1; } ? a.b) ]
#---
let s = { a = if s ? a then 1 else 2; b = throw "b"; }; in [ s.a (s ? b) (s ? a.x) ({ a.b = throw "x"; } ? a.b) ]
#---
({ a = 1; }).b or "default"
#---
let x = null; in x.y or 5
#---
builtins.placeholder "out"
#---
builtins.convertHash { hash = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; toHashFormat = "nix32"; }
#---
[ (builtins.elem 2 [ 1 2 3 ]) (builtins.all (x: x > 0) [ 1 2 ]) (builtins.any (x: x > 5) [ 1 2 ]) (builtins.head [ 1 2 ]) (builtins.tail [ 1 2 3 ]) (builtins.isFunction builtins.map) ]
#---
let f = { __functor = self: x: self.v + x; v = 10; }; in f 5
#---
let s = { __toString = self: "custom"; }; in "${s}"
#---
(derivation { name = "t"; system = "x"; builder = "/bin/sh"; }).outPath
#---
(derivation { name = "multi"; system = "x"; builder = "/bin/sh"; outputs = [ "out" "dev" ]; }).dev.outPath
#---
let d = derivation { name = "dep"; system = "x"; builder = "/bin/sh"; }; in (derivation { name = "top"; system = "x"; builder = "/bin/sh"; args = [ "-c" "echo ${d}" ]; }).drvPath
#---
(derivation { name = "fod"; system = "x"; builder = "/bin/sh"; outputHash = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; outputHashMode = "recursive"; }).outPath
#---
(derivation { name = "fod"; system = "x"; builder = "/bin/sh"; outputHashAlgo = "sha256"; outputHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"; }).drvPath
#---
let d = derivation { name = "fod"; system = "x"; builder = "/bin/sh"; outputHash = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; }; in (derivation { name = "usefod"; system = "x"; builder = "/bin/sh"; src = d; }).drvPath
#---
(derivation { name = "sa"; system = "x"; builder = "/bin/sh"; __structuredAttrs = true; foo = [ 1 "a" { b = true; } ]; }).drvPath
#---
(derivation { name = "iz"; system = "x"; builder = "/bin/sh"; __ignoreNulls = true; foo = null; bar = 1; }).drvPath
#---
(derivation { name = "src"; system = "x"; builder = "/bin/sh"; src = builtins.toFile "s" "content"; }).drvPath
#---
builtins.getContext (derivation { name = "t"; system = "x"; builder = "/bin/sh"; }).drvPath
#---
builtins.getContext "${derivation { name = "t"; system = "x"; builder = "/bin/sh"; }}"
#---
let x = { a = 1; inherit (y) b; }; y = { b = 2; }; in x
#---
let inherit (builtins) length; in length [ 1 2 ]
#---
{ inherit (builtins) true; }
#---
builtins.attrValues { b = 2; a = 1; }
#---
[ (builtins.seq 1 2) (builtins.deepSeq [ 1 ] 2) ]
#---
let { body = a; a = 3; }
#---
[ 1e3 .5 1.5e-2 ]
#---
builtins.toJSON (builtins.fromJSON "1e3")
#---
(import <nix/fetchurl.nix> { url = "https://example.com/x.tar.gz"; sha256 = "0000000000000000000000000000000000000000000000000000"; }).drvPath
#---
let pkgs = { a = 1; }; in let inherit (pkgs) a; b = a + 1; in b
#---
let x = rec { a = 1; inherit (x2) c; }; x2 = { c = 3; }; in x
#---
{ a = { b = 1; }; a.c = 2; }
#---
builtins.path { path = /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib/default.nix; }
#---
"${/nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/pkgs/stdenv/generic/setup.sh}"
#---
builtins.filterSource (p: t: t != "directory" || baseNameOf p != "tests") /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib
#---
builtins.readDir /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib/fileset
#---
(import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib).version
#---
with import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib; [ (versionAtLeast "2.3" "2.1") (concatMapStringsSep "-" toUpper [ "a" "b" ]) (attrsets.recursiveUpdate { a.b = 1; } { a.c = 2; }) (strings.escapeShellArg "it's") (lists.unique [ 1 2 1 3 ]) (fix (s: { x = 1; y = s.x; })).y ]
#---
with import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib; (evalModules { modules = [ { options.foo = mkOption { type = types.int; default = 3; }; } { foo = mkForce 5; } ]; }).config
#---
with import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source/lib; (systems.elaborate "aarch64-darwin").config
#---
(import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source {}).hello.drvPath
#---
(import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source {}).hello.outPath
#---
(import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source {}).python3.drvPath
#---
(import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source {}).git.drvPath
#---
(import /nix/store/smgkshm3r00a4rl7gw5ymgfqsd2k573l-source {}).poppler.drvPath
#---
builtins.fromTOML "a = 1\nb = \"x\\ty\\u00e9\\U0001F600\"\nc = 'lit\\n'\nd = \"\"\"\nmulti\nline \\\n   cont\"\"\"\ne = '''\nraw\\n'''\nf = 0xff\ng = 0o17\nh = 0b101\ni = 1_000\nj = 3.14\nk = 1e3\nl = -0.0\nm = true\nn = [1, 2, [3, \"x\"]]\no = { x = 1, y.z = 2 }\n\"quoted key\" = 1\np.q.r = 3\n[t]\nu = 1\n[t.v]\nw = 2\n[[arr]]\nx = 1\n[[arr]]\nx = 2\n[[arr.sub]]\ny = 3\n"
#---
builtins.fromTOML "a = inf\nb = -inf\nc = +1\nd = +1.5\ne = nan\nf = 1e100\ng = 1e-7\nh = 1_0.5_0\ni = 5e-1"
#---
builtins.fromTOML "a = 9223372036854775808\nb = -9223372036854775809\nc = 0xDEAD_beef"
#---
builtins.fromTOML "[a.b]\nc = 1\n[a]\nd = 2\n[[x]]\n[[x]]\ny = 1\n[[x.z]]\n[x.w]\n[ 'k y' . \"z\" ]\nv = 2"
#---
builtins.fromTOML "a = [ 1,\n  2, # comment\n]\nb = [[1], ['x']]\nc = [{x=1},{y=2}]\nd = {}\n\"\" = 1\n1 = 2\n3.4 = 5\ntrue = 1 # trailing\r\n"
#---
builtins.fromTOML "a = \"\"\"\nx\"\"\"\"\"\nb = '''\n'''\nc = \"\\u0000\"\nd = \"\"\"\\\n\n  y\"\"\""
#---
builtins.fromTOML "a = 1979-05-27T07:32:00Z"
#---
builtins.fromTOML "a = 07:32:00"
#---
builtins.fromTOML "a = 1\na = 2"
#---
builtins.fromTOML "a.b = 1\n[a]\nc = 2"
#---
builtins.fromTOML "a = {b = 1}\n[a.c]\nd = 1"
#---
builtins.fromTOML "[a]\n[[a]]"
#---
builtins.fromTOML "a = { b = 1, }"
#---
builtins.fromTOML "a = 01"
#---
builtins.fromTOML "a = -0xff"
#---
builtins.fromTOML "a = \"\\x41\""
#---
builtins.toXML [ 1 (-2) 1.5 0.1 1.0e20 0.000001 123456789.0 "s<>&\"'\n\r\tx" true false null /tmp/x [] {} ]
#---
builtins.toXML { b = 1; a = { c = [ 2 ]; }; "q\"" = 3; f = let x = 1; in x; g = builtins.map (x: x) [ 1 ]; }
#---
builtins.toXML [ (x: x) ({ a, b ? 1, ... }: a) ({ z, a }@args: a) ({ z, a, ... }@args: a) builtins.map (builtins.map (x: x)) { __toString = s: "x"; } ]
#---
builtins.toXML { a = derivation { name = "x"; system = "x86_64-linux"; builder = "/bin/sh"; }; b = derivation { name = "x"; system = "x86_64-linux"; builder = "/bin/sh"; }; }
#---
builtins.toXML [ { type = "derivation"; } { type = "derivation"; drvPath = "/nix/store/x.drv"; outPath = "/nix/store/x"; z = 1; } { type = "derivation"; drvPath = 1; outPath = "/x"; } { outPath = "/x"; } ]
#---
builtins.getContext (builtins.toXML (derivation { name = "x"; system = "x86_64-linux"; builder = "/bin/sh"; }))
#---
builtins.getContext (builtins.toXML [ "${derivation { name = "x"; system = "x86_64-linux"; builder = "/bin/sh"; }}" ])
#---
builtins.toXML [ (throw "x") ]
