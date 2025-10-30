> [!Warning]
> This project is in early development, it does however work with real sats! Always use amounts you don't mind losing.

# High-frequency Cashu payments

This is a basic demo of a Spillman Channel, i.e. unidirectional, for sending small amounts of bitcoin in many micropayments.
The emphasis is on efficiency and scalability; compared to the naive approach of preparing and redeeming one token for each micropayment, we use a small number of proofs (1 sat, 2 sats, 4 sats, 8sats, ...) to enable the balance to be easily increased by combining the proofs in the right way.

# Quick start

```
git clone git@github.com:SatsAndSports/demo_of_spillman_cashu_channel.git
cd demo_of_spillman_cashu_channel
```

As of 2025-10-30, all the code for this demo is in `crates/cdk/examples/spillman_channel.rs` and can be run with:

```
time cargo run --example spillman_channel -- --delay-until-refund 20
```

that demo runs for about two minutes, making 100,000 micropayments from Alice to Bob, where.

This demo is based on the CDK, as it uses the CDK wallet and CDK mint.

See below for more on the data structures, and how you could extend this or use this in your application.

# Licence

??? What's the CDK license?

# Trustless

While both parties (the sender and the recipient) both need to trust the mint, in this system they do not need to trust each other. The sender 'funds' the channel, and the recipient has unilateral exit at any time. The sender can reclaim the unspent portion of the channel funding, in the event that the recipient isn't cooperative.

A text description of the system:

https://github.com/cashubtc/nuts/pull/296/files


# Data structures

TODO: describe the following:

 - `ChannelParameters` - the two public keys, the unit (msat/sat/USC), the total channel capacity.
 - `ChannelFixtures` - the proofs. Shared and verified by both parties. Once these are set, the channel is 'open' and no further communication is needed until the receiver wishes to exit
 - `BalanceUpdateMessage`, the small message that Alice sends to Bob to inform him of the new balance, and to give him her signature. Includes a method `.verify` to allow Bob to verify that Alice's signature is genuine. Verification does not require talking to the mint
