#!/bin/bash
set -e
cd "$(dirname "$0")"
cd backend && CGO_ENABLED=0 GOOS=wasip1 GOARCH=wasm go build -ldflags="-s -w" -o plugin.wasm main.go && cd ..
zip -r azure-kv-plugin.zip plugin.json README.md icon.svg frontend/ backend/main.go backend/go.mod backend/plugin.wasm
