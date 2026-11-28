# Packages for tests/profiles.py: small `/bin/sh` builds with a program
# in `bin`, in two versions so that upgrades have something to do.
{ version ? 1 }:
let
  pkg = name: ver: { meta ? { }, ... }@extra:
    derivation ({
      name = "${name}-${toString ver}.0";
      system = builtins.currentSystem;
      builder = "/bin/sh";
      args = [
        "-c"
        ''
          /bin/mkdir -p $out/bin $out/share/${name}
          printf '#!/bin/sh\necho ${name} ${toString ver}\n' > $out/bin/${name}
          /bin/chmod +x $out/bin/${name}
          echo ${name} > $out/share/${name}/README
        ''
      ];
    } // removeAttrs extra [ "meta" ]) // { inherit meta; };
in
{
  hello = pkg "hello" version { };
  cowsay = pkg "cowsay" 1 { };
  # Provides `bin/hello` as well, at a lower priority than `hello`.
  hello-alt = pkg "hello-alt" 1 {
    meta.priority = 10;
    args = [ "-c" "/bin/mkdir -p $out/bin; printf '#!/bin/sh\\necho alt\\n' > $out/bin/hello; /bin/chmod +x $out/bin/hello" ];
  };
}
