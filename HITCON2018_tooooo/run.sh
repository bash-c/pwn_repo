#!/usr/bin/env bash
set -euxo pipefail

unset LD_LIBRARY_PATH
qemu-aarch64 -L ./ ./tooooo
