{ lib, stdenv
, buildPlatform, hostPlatform, targetPlatform
, pkgsBuildBuild
, callPackage
, linkFarm
, overrideCC, libcCross
, treeHelpers
, fetchurl
, qemu
}:

let
  superCallPackage = callPackage;
in

self:

let
  callPackage = self.callPackage;
in

let
  # HACK: unify across cross pkgsets
  callBuildBuildPackage = self.otherSplices.selfBuildBuild.callPackage;
in

let
  fenixRev = "260b00254fc152885283b0d2aec78547a1f77efd";
  fenixSource = fetchTarball "https://github.com/nix-community/fenix/archive/${fenixRev}.tar.gz";
  fenix = import fenixSource {};

  rustToolchainParams = {
    channel = "nightly";
    date = "2023-05-03";
    sha256 = "sha256-0oi6CUT7J1nJj0lCRQS/7qClvzY7TrgfchjURE7WqxE=";
    # TODO
    # loader crashes when profile.{}.debug = "2"
    # date = "2023-01-27";
    # sha256 = "sha256-JHs8yGthsweFSeamjAt2wzPh4ZeR4dsmHb9tcfT9k5A=";
  };

  mkRustToolchain = target: fenix.targets.${target}.toolchainOf rustToolchainParams;

  # TODO
  # rustToolchain = fenix.combine ([
  #   (mkRustToolchain hostPlatform.config).completeToolchain
  # ] ++ lib.optionals (hostPlatform.config != targetPlatform.config && !targetPlatform.isNone) [
  #   (mkRustToolchain targetPlatform.config).rust-std
  # ]);

  rustToolchain = (mkRustToolchain buildPlatform.config).completeToolchain;

in

superCallPackage ../rust-utils {} self //

(with self; {

  sources = callPackage ./sources.nix {};

  seL4Arch =
    lib.head
      (map
        (x: lib.elemAt x 1)
        (lib.filter
          (x: lib.elemAt x 0)
          (with hostPlatform; [
            [ isAarch64 "aarch64" ]
            [ isAarch32 "aarch32" ]
            [ isRiscV64 "riscv64" ]
            [ isRiscV32 "riscv32" ]
            [ isx86_64 "x86_64" ]
            [ isx86_32 "ia32" ]
          ])));

  ### rust

  defaultRustToolchain = rustToolchain;

  rustTargetArchName = {
    aarch64 = "aarch64";
    aarch32 = "armv7a";
    riscv64 = "riscv64imac";
    riscv32 = "riscv32imac";
    x86_64 = "x86_64";
    ia32 = "i686";
  }."${seL4Arch}";

  defaultRustTargetInfo =
    if !hostPlatform.isNone
    then mkBuiltinRustTargetInfo hostPlatform.config
    else seL4RustTargetInfoWithConfig {};

  seL4RustTargetInfoWithConfig = { cp ? false, minimal ? false }: mkCustomRustTargetInfo "${rustTargetArchName}-sel4${lib.optionalString cp "cp"}${lib.optionalString minimal "-minimal"}";

  bareMetalRustTargetInfo = mkBuiltinRustTargetInfo {
    aarch64 = "aarch64-unknown-none";
    aarch32 = "armv7a-none-eabi"; # armv7a-none-eabihf?
    riscv64 = "riscv64imac-unknown-none-elf"; # gc?
    riscv32 = "riscv32imac-unknown-none-elf"; # gc?
    x86_64 = "x86_64-unknown-none";
    ia32 = "i686-unknown-linux-gnu";
  }."${seL4Arch}";

  mkBuiltinRustTargetInfo = name: {
    inherit name;
    path = null;
  };

  mkCustomRustTargetInfo = name: {
    inherit name;
    path =
      let
        fname = "${name}.json";
      in
        linkFarm "targets" [
          { name = fname; path = sources.srcRoot + "/support/targets/${fname}"; }
        ];
  };

  chooseLinkerForRustTarget = { rustToolchain, rustTargetName, platform }:
    if platform.isNone
    then "${rustToolchain}/lib/rustlib/${buildPlatform.config}/bin/rust-lld"
    else null;

  inherit (callPackage ./crates.nix {}) crates;

  distribution = callPackage ./distribution.nix {};

  registry = callPackage ./registry.nix {};

  buildCrateInLayersHere = buildCrateInLayers {
    # TODO pass vendored lockfile instead
    superLockfile = topLevelLockfile;
  };

  topLevelLockfile = sources.srcRoot + "/Cargo.lock";

  vendoredTopLevelLockfile = vendorLockfile { lockfile = topLevelLockfile; };

  # HACK: reduce closure size, llvm now depends on targetPackage
  libclangPath = "${lib.getLib pkgsBuildBuild.llvmPackages.libclang}/lib";

  ### upstream tools

  capdl-tool = callBuildBuildPackage ./capdl-tool {};

  ### misc tools

  cargo-index = callPackage ./tools/cargo-index.nix {};

  ### local tools

  mkTool = rootCrate: buildCrateInLayersHere {
    inherit rootCrate;
    release = false;
  };

  sel4-backtrace-embedded-debug-cli = mkTool crates.sel4-backtrace-embedded-debug-info-cli;
  sel4-backtrace-cli = mkTool crates.sel4-backtrace-cli;
  sel4-capdl-initializer-add-spec = mkTool crates.sel4-capdl-initializer-add-spec;
  sel4-simple-task-runtime-config-cli = mkTool crates.sel4-simple-task-runtime-config-cli;
  sel4-kernel-loader-add-payload = mkTool crates.sel4-kernel-loader-add-payload;

  embedDebugInfo = callPackage ./embed-debug-info.nix {};

  cargo-helpers = callPackage ./tools/cargo-helpers.nix {};

  shell = callPackage ./shell.nix {};

  ### kernel

  mkSeL4 = callPackage ./sel4 {};

  mkSeL4CorePlatform = callPackage ./sel4cp {};

  cmakeConfigHelpers = callPackage ./cmake-config-helpers.nix {};

  ### worlds

  mkWorld = unelaboratedWorldConfig: lib.makeScope newScope (callPackage ./world {} unelaboratedWorldConfig);

  worlds = (callPackage ./worlds.nix {})."${seL4Arch}";

  platUtils = callPackage ./plat-utils {};

  ### sel4test

  mkSeL4Test = callPackage ./sel4test {};

  # TODO name more configurations
  sel4test = makeOverridable' mkSeL4Test {
    rust = hostPlatform.is64bit;
  };

  ### helpers

  # Like to `lib.callPackageWith`, except without `lib.makeOverridable`.
  callWith = autoArgs: fn: args:
    let
      f = if lib.isFunction fn then fn else import fn;
      auto = builtins.intersectAttrs (lib.functionArgs f) autoArgs;
    in f (auto // args);

  # Like `lib.makeOverridable`, except it adds an orthogonal dimension of overrideablility
  # accessible at `.override'`.
  makeOverridable' = f: origArgs:
    let
      overrideWith = newArgs: origArgs // (if lib.isFunction newArgs then newArgs origArgs else newArgs);
    in f origArgs // {
      override' = newArgs: makeOverridable' f (overrideWith newArgs);
    };

  ### cargo manifest generation utils

  cargoManifestGenrationUtils = callPackage ../cargo-manifest-generation-utils {};

  generatedCargoManifests = callPackage ./generated-cargo-manifests {};

  ### QEMU

  qemuForSeL4 = (qemu.override {
    hostCpuTargets = [
      "arm-softmmu"
      "aarch64-softmmu"
      "riscv32-softmmu"
      "riscv64-softmmu"
      "i386-softmmu"
      "x86_64-softmmu"
    ];
    guestAgentSupport = false;
    numaSupport = false;
    seccompSupport = false;
    alsaSupport = false;
    pulseSupport = false;
    sdlSupport = false;
    jackSupport = false;
    gtkSupport = false;
    vncSupport = false;
    smartcardSupport = false;
    spiceSupport = false;
    ncursesSupport = false;
    usbredirSupport = false;
    libiscsiSupport = false;
    tpmSupport = false;
    uringSupport = false;
  }).overrideDerivation (attrs: {
    patches = attrs.patches ++ [
      (fetchurl {
        url = "https://github.com/coliasgroup/qemu/commit/cd3b78de4b5a8d7c79ae99dab2b5e0ab1ba0ffac.patch";
        sha256 = "sha256-bDmMyelaMCJWhr88XIKEBNMZP3VcBD3mOXhOWal3IBw=";
      })
    ];
  });

  ### stdenv

  stdenvWithLibc =
    let
      bintools = stdenv.cc.bintools.override {
        libc = libcCross;
        noLibc = false;
      };
    in
      stdenv.override {
        cc = stdenv.cc.override {
          libc = libcCross;
          noLibc = false;
          inherit bintools;
        };
      };

})
