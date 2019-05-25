#!/bin/sh

rm -rf tmp

mkdir tmp
cd tmp

git clone -b 'mbedtls-2.16.1' --single-branch --depth 1 --recurse-submodules https://github.com/ARMmbed/mbedtls

cd mbedtls
mkdir build && cd $_

cmake ..
make
make test

cd ../../../