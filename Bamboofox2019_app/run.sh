#!/bin/bash
cd $(dirname $0)
sudo chroot --userspec=65534:65534 app /app
