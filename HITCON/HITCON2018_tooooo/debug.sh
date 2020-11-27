#!/usr/bin/env bash
set -euxo pipefail

unset LD_LIBRARY_PATH
qemu-aarch64 -g 1234 -L ./ ./tooooo
