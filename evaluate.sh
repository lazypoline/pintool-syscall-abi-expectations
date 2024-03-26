#!/bin/bash

# Compile Pin tool
make PIN_ROOT=/root/pin-3.28-98749-g6643ecee5-gcc-linux/

# Run Pin tool
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- ls
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- pwd
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- mkdir dir
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- mv dir pinout/
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- chmod +w dir
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- cp -r pinout/dir dir2 
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- rm -r dir2/
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- touch pinout/dir/
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- cat README.md
../pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/syscallregdeps.so -- clear