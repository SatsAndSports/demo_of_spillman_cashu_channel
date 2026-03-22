# Spilman Channel Low-Level Example

This directory contains a low-level example and tests for the Spilman Channel protocol implementation. It demonstrates the raw mechanics of channel funding, payment signing, and closing without the abstractions provided by the `SpilmanBridge`.

## Overview

The example demonstrates:
1.  **Key Generation**: Creating secp256k1 keys for Alice (sender) and Charlie (receiver).
2.  **Channel Parameters**: Defining capacity, expiry timestamp, and deriving the `_channel secret_`.
3.  **Funding**: Creating the 2-of-2 multisig funding token.
4.  **Payments**: Alice signing incremental balance updates.
5.  **Closing**: Charlie verifying signatures and settling with the mint.

## Running the Example

```bash
# Run the example with verbose output
cargo run --example spilman_channel
```

You can also point the example at an external mint (must support NUT-11 SIG_ALL):
```bash
cargo run --example spilman_channel -- --mint http://localhost:3338
```

## Running Tests

This directory contains unit and integration tests for the core Spilman logic:

```bash
cargo test --example spilman_channel
```

The tests in `sender_and_receiver.rs`, specifically `test_full_flow`, provide a complete walk-through of the channel lifecycle.

---

## Technical Details

### Mints with non-powers-of-2 keysets

The Spilman implementation is tested against keysets with various bases (e.g., powers-of-3) to ensure the deterministic output splitting logic is robust across different mint configurations.

### Nutshell Integration

The example is compatible with the [Nutshell](https://github.com/cashubtc/nutshell) mint (version 0.18.2+). 

To run with Nutshell:
1. Start Nutshell with the SIG_ALL message update.
2. Run the example using the `--mint` flag.
