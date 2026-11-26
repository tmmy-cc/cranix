# Content-addressed and impure derivations for tests/catest.py.
{ system, salt ? "", log ? "/dev/null" }:
let
  ca = name: script: extra:
    derivation ({
      inherit name system;
      builder = "/bin/sh";
      args = [ "-c" script ];
      __contentAddressed = true;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";
    } // extra);

  # `salt` changes the derivation but leaves its output unchanged.
  a = ca "a" "echo hello > $out" { inherit salt; };

  # References `a` and itself; records each run of its builder in `log`.
  b = ca "b" ''
    echo b >> ${log}
    /bin/mkdir $out
    echo ${a} > $out/a
    echo $out > $out/self
  '' { };

  # Input-addressed, but deferred until `b` is built.
  c = derivation {
    name = "c";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" "echo ${b} > $out" ];
  };

  # `out` refers to `dev`, so `dev` gets its final path first.
  multi = ca "multi" ''
    /bin/mkdir $out $dev
    echo $dev > $out/dev
    echo header > $dev/h
  '' { outputs = [ "out" "dev" ]; };

  # Text-hashed like `builtins.toFile`, with a reference to `a`.
  text = ca "text" "echo ${a} > $out" { outputHashMode = "text"; };

  textFixed = derivation {
    name = "text-fixed";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" "printf hello > $out" ];
    outputHashMode = "text";
    outputHash = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
  };

  i = derivation {
    name = "i";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" "/bin/date +%s%N > $out" ];
    __impure = true;
  };
in
{ inherit a b c multi text textFixed i; }
