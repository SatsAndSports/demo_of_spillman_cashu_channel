This is a standalone-workspace skeleton for the first-wave Spilman crates.

Included members:
- `crates/cdk-spilman`
- `crates/cdk-spilman-interop-tests`
- `crates/cdk-wasm`
- `examples/rust-ascii-art`

Temporary note:
- `cashu` currently comes from the upstream `cashubtc/cdk` repo at a pinned git revision
- this keeps the skeleton off the local fork while the split is in progress

Smoke checks:

```bash
cargo test -p cdk-spilman
cargo test -p cdk-spilman-interop-tests
cargo test -p cdk-wasm --no-run
cargo test -p rust-ascii-art --no-run
```
