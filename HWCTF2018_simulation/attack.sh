#!/usr/bin/env bash
set -euxo pipefail

gcc ./solve.c -static -o solve
mv ./solve ./fs
cd ./fs
find . | cpio -o --format=newc > rootfs.cpio
mv ./rootfs.cpio ..
