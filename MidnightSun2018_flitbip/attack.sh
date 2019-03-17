#!/usr/bin/env bash
set -euxo pipefail

gcc ./solve.c -static -g -masm=intel -o solve
# musl-gcc ./solve.c -static -s -Os -masm=intel -o solve
mv ./solve ./rootfs/tmp/
cd ./rootfs
find . | cpio -o --format=newc > initrd.cpio
mv ./initrd.cpio ..
cd ..
./run.sh
