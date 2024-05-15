#
# Copyright 2023, Colias Group, LLC
#
# SPDX-License-Identifier: BSD-2-Clause
#

BUILD ?= .

build_dir := $(BUILD)
target_dir := $(build_dir)/target

.PHONY: none
none:

.PHONY: check
check:
	verus ../../crates/sel4/bitfield-ops/src/lib.rs
