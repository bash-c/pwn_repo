#!/usr/bin/env bash
set -euxo pipefail

gcc exploit.c -static -masm=intel -g -o exploit
cp exploit core/tmp 
cd core
./gen_cpio.sh core.cpio
mv core.cpio ..
cd ..

