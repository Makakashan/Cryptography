#!/usr/bin/env sh
set -eu

go build -o block block.go

echo "Build complete: ./block"
