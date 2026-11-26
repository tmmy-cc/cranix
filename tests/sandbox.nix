# Sandbox isolation test, driven by crates/oxnix/tests/sandbox.rs.
#
# `probe` records whether its builder could read `secret` (a host file
# outside its closure) and connect to `port` on the host's loopback
# interface. `fetch` is fixed-output and reads one line from that port;
# sandboxes keep the network open to it. Only bash builtins are used, so
# `probe` and `fetch` need nothing besides `bash` in the sandbox.
{
  secret,
  port,
  bash ? "/bin/bash",
  sleep ? "/bin/sleep",
  # Varies the derivations, so one store can build them in several modes.
  tag ? "",
}:
let
  sh = name: script: extra:
    derivation ({
      name = "${name}${tag}";
      system = builtins.currentSystem;
      builder = bash;
      args = [ "-c" script ];
    } // extra);
in
{
  probe = sh "sandbox-probe" ''
    {
      if read -r _ < ${secret}; then echo "read: allowed"; else echo "read: denied"; fi
      if exec 3<>/dev/tcp/127.0.0.1/${port}; then echo "network: allowed"; else echo "network: denied"; fi
      read -r host < /proc/sys/kernel/hostname && echo "hostname: $host"
      echo "uid: $UID"
      echo "build-top: $NIX_BUILD_TOP"
    } > $out
  '' { };

  # Probes like `probe`; `__noChroot` exempts it in relaxed mode.
  nochroot = sh "sandbox-nochroot" ''
    if read -r _ < ${secret}; then echo "read: allowed"; else echo "read: denied"; fi > $out
  '' { __noChroot = true; };

  fetch = sh "sandbox-fetch" ''
    exec 3<>/dev/tcp/127.0.0.1/${port}
    read -r line <&3
    echo "$line" > $out
  '' {
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    outputHash = builtins.hashString "sha256" "hello from the network\n";
  };

  # Runs past any timeout, with a background process that holds the log
  # pipe open.
  slow = sh "sandbox-slow" ''
    ${sleep} 1000 &
    echo started
    ${sleep} 1000
  '' { };
}
