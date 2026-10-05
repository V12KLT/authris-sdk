#!/bin/sh
set -e
cd "$(dirname "$0")"
echo "Building authv4.dll, needs mingw-w64, libcurl and OpenSSL dev files."
x86_64-w64-mingw32-gcc -shared -O2 -o authv4.dll authv4.c authv4.def -lcurl -lcrypto
mkdir -p ../dist
cp authv4.dll ../dist/authv4.dll
echo "Wrote sdk/dist/authv4.dll"
