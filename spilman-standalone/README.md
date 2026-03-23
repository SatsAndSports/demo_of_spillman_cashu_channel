This is a standalone-workspace skeleton for the first-wave Spilman crates.

Included members:
- `crates/cdk-spilman`
- `crates/cdk-wasm`
- `examples/rust-ascii-art`

Temporary note:
- `cashu` is still patched to the local fork via `[patch.crates-io]` in `Cargo.toml`
- this keeps the skeleton buildable while the split is in progress

Smoke checks:

```bash
cargo test -p cdk-spilman
cargo test -p cdk-wasm --no-run
cargo test -p rust-ascii-art --no-run
```
