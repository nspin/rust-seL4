#
# Copyright 2024, Colias Group, LLC
#
# SPDX-License-Identifier: BSD-2-Clause
#

{ lib
, stdenv
, buildPackages
, writeScript

, sources
, microkit
, qemuForSeL4
}:

let
  src = sources.sddf;

  echoServer = stdenv.mkDerivation {
    name = "x";
    inherit src;

    MICROKIT_CONFIG = microkit.config;
    MICROKIT_BOARD = microkit.board;
    MICROKIT_SDK = microkit.sdk;
    MICROKIT_TOOL = microkit.toolExe;

    configurePhase = ''
      cd examples/echo_server
    '';

    buildPhase = ''
      make all
    '';

    installPhase = ''
      cp -r build $out
    '';

    dontFixup = true;
  };

  runEchoServer = writeScript "automate-qemu" ''
    #!${buildPackages.runtimeShell}
    set -eu

    ${buildPackages.this.qemuForSeL4}/bin/qemu-system-aarch64 -machine virt,virtualization=on \
      -cpu cortex-a53 \
      -serial mon:stdio \
      -device loader,file=${echoServer}/loader.img,addr=0x70000000,cpu-num=0 \
      -m size=2G \
      -nographic \
      -device virtio-net-device,netdev=netdev0 \
      -netdev user,id=netdev0,hostfwd=tcp::1236-:1236,hostfwd=tcp::1237-:1237,hostfwd=udp::1235-:1235 \
      -global virtio-mmio.force-legacy=false \
      -d guest_errors
  '';
in {
  inherit echoServer;
  inherit runEchoServer;
}
