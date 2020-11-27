#!/bin/bash
cd $(dirname $0)
echo "BAMBOOFOX{aaaaaaaaaaaaaaaaaaaaa}" > app/flag1
echo "BAMBOOFOX{bbbbbbbbbbbbbbbbbbbbb}" > app/flag2
chmod 0400 app/flag2
sudo chown root:root -R app
sudo chmod +s app/read_flag

sudo apt install apparmor apparmor-utils apparmor-profiles -y
sudo aa-autodep app/read_flag
sudo aa-enforce app/read_flag

