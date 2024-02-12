#
# Copyright 2023, Colias Group, LLC
#
# SPDX-License-Identifier: BSD-2-Clause
#

{ mk, localCrates, versions, smoltcpWith }:

mk {
  package.name = "sel4-async-network";
  dependencies = {
    inherit (localCrates) sel4-async-network-traits;
    inherit (versions) log embedded-io-async;
    futures = {
      version = versions.futures;
      default-features = false;
      features = [
        "alloc"
      ];
    };
    smoltcp = smoltcpWith [
      "async"
      "alloc"
      # "verbose"
    ];
  };
}
