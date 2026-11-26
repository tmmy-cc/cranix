# Build test for `cranix --store DIR build -f tests/build.nix`.
let
  sh = args: name: extra:
    derivation ({
      inherit name;
      system = builtins.currentSystem;
      builder = "/bin/sh";
      args = [ "-c" args ];
    } // extra);

  # Independent leaves, built in parallel.
  leaves = map (i: sh "sleep 1; echo leaf ${toString i} > $out" "leaf-${toString i}" { }) [ 1 2 3 4 ];

  # References its inputs, so they end up in its closure.
  joined = sh ''
    /bin/mkdir $out
    for l in ${toString leaves}; do /bin/cat $l >> $out/all; done
    echo ${builtins.elemAt leaves 0} > $out/ref
  '' "joined" { };

  textFile = sh ''/bin/cat "$contentPath" > $out'' "pass-as-file" {
    content = "passed as a file";
    passAsFile = [ "content" ];
  };

  multi = sh ''/bin/mkdir $out $dev; echo lib > $out/lib; echo hdr > $dev/h'' "multi" {
    outputs = [ "out" "dev" ];
  };

  fixed = sh "printf hello > $out" "fixed" {
    outputHashAlgo = "sha256";
    outputHash = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
  };
in
[ joined textFile multi.dev fixed ]
