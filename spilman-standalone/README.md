This is a standalone workspace for the Spilman payment channels library.

Included members:
- `crates/cdk-spilman` — core protocol library
- `crates/cdk-spilman-go` — Go bindings (C FFI)
- `crates/cdk-spilman-interop-tests` — upstream `cdk` wallet interop coverage
- `crates/cdk-spilman-python` — Python bindings (PyO3)
- `crates/cdk-wasm` — WASM bindings
- `examples/rust-ascii-art` — Rust demo server

Note:
- `cashu` currently comes from the upstream `cashubtc/cdk` repo at a pinned git revision
- this keeps the workspace off the local fork while the split is in progress

Rust tests:

```bash
make test-standalone          # from the repo root
```

Binding builds:

```bash
# Go (build + unit tests)
make -C crates/cdk-spilman-go test-dev

# Python (build + install into local venv)
make -C crates/cdk-spilman-python build
```
