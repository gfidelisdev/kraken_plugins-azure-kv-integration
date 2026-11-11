---
title: compilacao-wasm-wasip1
author: Guilherme
date: 2026-11-06
branch: master
id: l-7a3be989
scope: repo
status: active
src: agent
touches:
  - azure-kv-plugin.zip
  - backend/plugin.wasm
---

## Decided
Sempre compilar o backend WASM com CGO_ENABLED=0 GOOS=wasip1 GOARCH=wasm go build -ldflags="-s -w" -o plugin.wasm main.go.

## Tried and ruled out
Compilar com GOOS=js GOARCH=wasm: gera binário visando browser/Node.js que depende do módulo host 'gojs' (wasm_exec.js). O Kraken usa runtime wazero isolado com apenas wasi_snapshot_preview1 e host kraken, falhando na inicialização com 'failed to instantiate wasm module: module[gojs] not instantiated'.

## Watch out
O Kraken Manager só faz auto-build se plugin.wasm não existir ou tiver tamanho < 1024 bytes. Se um plugin.wasm inválido (> 1KB) estiver no zip ou pasta instalada, o Kraken usa o binário existente sem recompilar.
