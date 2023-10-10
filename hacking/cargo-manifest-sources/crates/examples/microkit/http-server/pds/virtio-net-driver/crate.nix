{ mk, localCrates, versions, virtioDriversWith }:

mk {
  package.name = "microkit-http-server-example-virtio-net-driver";
  dependencies = rec {
    inherit (versions) log;

    smoltcp = {
      version = versions.smoltcp;
      default-features = false;
        features = [
          "proto-ipv4" "medium-ethernet" "socket-raw"
      ];
    };

    virtio-drivers = virtioDriversWith [ "alloc" ];

    sel4-externally-shared.features = [ "unstable" ];
    sel4-microkit = { default-features = false; };
  };
  nix.local.dependencies = with localCrates; [
    sel4-microkit
    sel4-microkit-message
    sel4
    sel4-sync
    sel4-logging
    sel4-immediate-sync-once-cell
    sel4-externally-shared
    sel4-shared-ring-buffer
    sel4-bounce-buffer-allocator
    sel4-hal-adapters

    microkit-http-server-example-virtio-hal-impl
    microkit-http-server-example-smoltcp-phy-impl
  ];
}
