# CDK Spilman Python Bindings

Python bindings for Spilman payment channels using PyO3.

This package provides both server-side (SpilmanBridge) and client-side functions for implementing Spilman unidirectional payment channels.

## Installation

### From Source (requires Rust)

```bash
# Using the Makefile
make build

# Or manually
pip install maturin
maturin develop
```

### From PyPI (coming soon)

```bash
pip install cdk-spilman
```

## Usage

### Server-Side (Receiver)

```python
from cdk_spilman import SpilmanBridge

class MyHost:
    """Implement SpilmanHost methods for your application."""
    
    def get_amount_due(self, channel_id: str, context: str | None) -> int:
        return 10  # Your pricing logic
    
    def receiver_key_is_acceptable(self, pubkey: str) -> bool:
        return pubkey == self.server_pubkey
    
    # ... implement other required methods

# Create bridge with your host
bridge = SpilmanBridge(MyHost(), server_secret_key_hex)

# Process payments
result = bridge.process_payment(payment_json, context_json)
print(f"Payment accepted: balance={result.balance}, channel={result.channel_id}")
```

### Client-Side (Sender)

```python
from cdk_spilman import (
    generate_keypair,
    compute_channel_secret,
    channel_parameters_get_channel_id,
    create_funding_outputs,
    create_signed_balance_update,
)

# Generate keypair
secret, pubkey = generate_keypair()

# Compute shared secret with receiver
channel_secret = compute_channel_secret(secret, receiver_pubkey)

# Get channel ID
channel_id = channel_parameters_get_channel_id(params_json, channel_secret, keyset_json)

# Create funding outputs for minting
funding = create_funding_outputs(params_json, secret, keyset_json)

# Create signed payment
payment = create_signed_balance_update(params_json, keyset_json, secret, proofs_json, balance)
```

## Testing

### Integration Tests

Integration tests require a Cashu mint running:

```bash
# Start a mint (from CDK repo root)
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# In another terminal, run integration tests
make test-integration

# Or with custom mint URL
MINT_URL=http://my-mint:3338 make test-integration
```

### Full Integration Suite

The comprehensive 52-test integration suite is run from the CDK root:

```bash
# From CDK repository root
make test-server-python
```

## Example Server

An ASCII art demo server is included:

```bash
# Start the server
make run-server

# In another terminal, run the client
make run-client
```

See `examples/ascii-art/README.md` for more details.

## API Reference

### Classes

- `SpilmanBridge` - Main bridge for server-side payment validation
- `PaymentSuccess` - Result of a successful payment
- `PaymentValidationResult` - Result of payment validation (without recording)
- `FundChannelResult` - Result of channel registration
- `CloseSuccess` - Result of channel closing

### Functions

- `generate_keypair()` - Generate a new secp256k1 keypair
- `secret_key_to_pubkey(secret_hex)` - Derive public key from secret
- `compute_channel_secret(my_secret, their_pubkey)` - Compute ECDH shared secret
- `channel_parameters_get_channel_id(params_json, channel_secret, keyset_json)` - Get channel ID
- `create_funding_outputs(params_json, secret, keyset_json)` - Create blinded outputs for funding
- `construct_proofs(signatures_json, secrets_json, keyset_json)` - Construct proofs from signatures
- `create_signed_balance_update(params_json, keyset_json, secret, proofs_json, balance)` - Sign a payment
- `unblind_and_verify_dleq(...)` - Unblind signatures and verify DLEQ proofs

## Protocol

See [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) for the full protocol specification.

## License

MIT
